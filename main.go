package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

const browserUA = "Dalvik/2.1.0 (Linux; U; Android 16; SM-S901W Build/BP2A.250605.031.A3)"
const clientID = "4b3a6465-94dd-47c2-976c-18bc29c53c2f"

type ExchangedAuthTokenResponse struct {
	AccessToken           string `json:"access_token"`
	IDToken               string `json:"id_token"`
	TokenType             string `json:"token_type"`
	NotBefore             int    `json:"not_before"`
	ExpiresIn             int    `json:"expires_in"`
	ExpiresOn             int    `json:"expires_on"`
	Resource              string `json:"resource"`
	ClientInfo            string `json:"client_info"`
	Scope                 string `json:"scope"`
	RefreshToken          string `json:"refresh_token"`
	RefreshTokenExpiresIn int    `json:"refresh_token_expires_in"`
}

func expect(req *http.Request, resp *http.Response, status int) error {
	if resp.StatusCode != status {
		respText, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected response code %v %v %v: %v", resp.StatusCode, req.Method, req.URL, string(respText))

	}
	return nil
}

func NewCodeVerifier() string {
	return "DM6nhvQSKnj72gkQQ5T1tCgCYGy5vdXnzdIQw3Bh46TX7pDvAcisyWDyt5UL3NQH8q4NoqMvRICQRmxCeDU3qHj8Jvciqo4RHcRiyjIlbB9q0k8LnUu8zHIdJHRLtk3J" // idc
}

func CodeVerifierToChallenge(codeVerifier string) string {
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func NewLoginURL(codeVerifier string) string {
	data := url.Values{}
	data.Set("scope", "https://wattsb2cap02.onmicrosoft.com/wattsapiresi/manage+offline_access+openid+profile")
	data.Set("response_type", "code")
	data.Set("client_id", clientID)
	data.Set("redirect_uri", "msal"+clientID+"://auth")
	data.Set("prompt", "login")
	data.Set("code_challenge", CodeVerifierToChallenge(codeVerifier))
	data.Set("code_challenge_method", "S256")
	data.Set("client_info", "1")
	data.Set("haschrome", "1")
	return fmt.Sprintf("https://login.watts.io/tfp/wattsb2cap02.onmicrosoft.com/B2C_1A_Residential_UnifiedSignUpOrSignIn/oauth2/v2.0/authorize?%v", data.Encode())
}

func LoginSelfAsserted(codeVerifier, username, password string) (string, error) {
	jar, _ := cookiejar.New(nil)

	client := http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// initial cookie booting
	loginURL := NewLoginURL(codeVerifier)
	req, _ := http.NewRequest("GET", loginURL, nil)
	req.Header.Set("User-Agent", browserUA)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	if err := expect(req, resp, http.StatusOK); err != nil {
		resp.Body.Close()
		return "", err
	}
	resp.Body.Close()
	var csrf string
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "x-ms-cpim-csrf" {
			csrf = cookie.Value
			break
		}
	}
	if csrf == "" {
		return "", errors.New("no csrf cookie found :(")
	}
	var transaction string
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "x-ms-cpim-trans" {
			type TransCookieStructure struct {
				TDic []struct {
					I string `json:"I"`
					T string `json:"T"`
					P string `json:"P"`
					C string `json:"C"`
					S int    `json:"S"`
					M struct {
					} `json:"M"`
					D int    `json:"D"`
					E string `json:"E"`
				} `json:"T_DIC"`
				CID string `json:"C_ID"`
			}
			dec, err := base64.StdEncoding.DecodeString(cookie.Value)
			if err != nil {
				return "", fmt.Errorf("failed to decode x-ms-cpim-trans cookie %v: %v", cookie.Value, err)
			}
			var unm TransCookieStructure
			if err := json.Unmarshal(dec, &unm); err != nil {
				return "", fmt.Errorf("failed to unmarshal x-ms-cpim-trans decoded cookie value %v: %v", dec, err)
			}
			transaction = unm.CID
		}
	}
	if transaction == "" {
		return "", errors.New("no transaction cookie found :(")
	}
	transactionEncoded := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("{\"TID\":\"%v\"}", transaction)))

	// submitting login form
	data := url.Values{}
	data.Set("request_type", "RESPONSE")
	data.Set("signInName", username)
	data.Set("password", password)
	selfAssertedURL := fmt.Sprintf("https://login.watts.io/wattsb2cap02.onmicrosoft.com/B2C_1A_Residential_UnifiedSignUpOrSignIn/SelfAsserted?tx=StateProperties=%v&p=B2C_1A_Residential_UnifiedSignUpOrSignIn", transactionEncoded)
	req, _ = http.NewRequest("POST", selfAssertedURL, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Referer", loginURL)
	req.Header.Set("X-CSRF-TOKEN", csrf)

	resp, err = client.Do(req)
	if err != nil {
		return "", err
	}
	if err := expect(req, resp, http.StatusOK); err != nil {
		resp.Body.Close()
		return "", err
	}
	resp.Body.Close()

	// confirming token
	confirmURL := fmt.Sprintf("https://login.watts.io/wattsb2cap02.onmicrosoft.com/B2C_1A_Residential_UnifiedSignUpOrSignIn/api/CombinedSigninAndSignup/confirmed?rememberMe=true&csrf_token=%v&tx=StateProperties=%v", csrf, transactionEncoded)
	req, _ = http.NewRequest("GET", confirmURL, nil)
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Referer", loginURL)

	resp, err = client.Do(req)
	if err != nil {
		return "", err
	}
	if err := expect(req, resp, http.StatusFound); err != nil {
		resp.Body.Close()
		return "", err
	}
	resp.Body.Close()

	redir, err := resp.Location()
	if err != nil {
		return "", err
	}

	code := redir.Query().Get("code")
	if code == "" {
		return "", fmt.Errorf("no code parameter found in redirect: %v", redir)
	}

	return code, nil
}

func ExchangeAuthToken(code, codeVerifier string) (ExchangedAuthTokenResponse, error) {
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("scope", "https://wattsb2cap02.onmicrosoft.com/wattsapiresi/manage+offline_access+openid+profile")
	data.Set("client_info", "1")
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", "msal"+clientID+"://auth")
	data.Set("code_verifier", codeVerifier)

	req, err := http.NewRequest("POST", "https://login.watts.io/tfp/wattsb2cap02.onmicrosoft.com/B2C_1A_Residential_UnifiedSignUpOrSignIn/oauth2/v2.0/token?haschrome=1", strings.NewReader(strings.ReplaceAll(data.Encode(), "%2B", "+")))
	if err != nil {
		return ExchangedAuthTokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", browserUA)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ExchangedAuthTokenResponse{}, err
	}
	defer resp.Body.Close()

	if err := expect(req, resp, http.StatusOK); err != nil {
		resp.Body.Close()
		return ExchangedAuthTokenResponse{}, err
	}

	var decoded ExchangedAuthTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return ExchangedAuthTokenResponse{}, err
	}

	return decoded, nil
}

const apiBaseURL = "https://home.watts.com/api"

type APIWrappedResponse[T any] struct {
	ErrorNumber  int `json:"errorNumber"`
	ErrorMessage any `json:"errorMessage"`
	Body         T   `json:"body"`
}

func API[T any](method, path string, body io.Reader, expectedStatus int, decode bool, token string) (T, error) {
	req, err := http.NewRequest(method, apiBaseURL+path, body)
	if err != nil {
		return *new(T), err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Api-Version", "2.0")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return *new(T), err
	}
	defer resp.Body.Close()

	if err := expect(req, resp, http.StatusOK); err != nil {
		return *new(T), err
	}

	var data T

	if decode {
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return *new(T), err
		}
	}

	return data, nil
}

func Get[T any](path, token string) (T, error) {
	return API[T]("GET", path, nil, http.StatusOK, true, token)
}

// func Patch[T any](path, token string, body io.Reader) (T, error) {
// 	return API[T]("PATCH", path, body, http.StatusOK, true, token)
// }

// func PatchJ[T any](path, token string, body any) (T, error) {
// 	d, err := json.Marshal(body)
// 	if err != nil {
// 		return *new(T), err
// 	}
// 	return Patch[T](path, token, bytes.NewReader(d))
// }

type UserDetails struct {
	UserID                   string `json:"userId"`
	EmailAddress             string `json:"emailAddress"`
	DefaultLocationID        string `json:"defaultLocationId"`
	LanguagePreference       string `json:"languagePreference"`
	UserTypeID               int    `json:"userTypeId"`
	MeasurementScale         string `json:"measurementScale"`
	MobilePhoneNumber        string `json:"mobilePhoneNumber"`
	FirstName                string `json:"firstName"`
	LastName                 string `json:"lastName"`
	SmsNotificationEnabled   bool   `json:"smsNotificationEnabled"`
	EmailNotificationEnabled bool   `json:"emailNotificationEnabled"`
	PushNotificationEnabled  bool   `json:"pushNotificationEnabled"`
	DefaultLocationDevices   []any  `json:"defaultLocationDevices"`
	VoiceControlPlatform     string `json:"voiceControlPlatform"`
}

func GetUserDetails(token string) (APIWrappedResponse[UserDetails], error) {
	return Get[APIWrappedResponse[UserDetails]]("/User/Details", token)
}

type Location struct {
	Address struct {
		Address       string `json:"address"`
		Address2      string `json:"address2"`
		City          string `json:"city"`
		Country       string `json:"country"`
		StateProvince string `json:"state_province"`
		Zipcode       string `json:"zipcode"`
	} `json:"address"`
	AwayState                      int    `json:"awayState"`
	DevicesCount                   int    `json:"devicesCount"`
	HasDeviceInDemandResponseEvent bool   `json:"hasDeviceInDemandResponseEvent"`
	IsDefault                      bool   `json:"isDefault"`
	IsShared                       bool   `json:"isShared"`
	LocationID                     string `json:"locationId"`
	Name                           string `json:"name"`
	OwnerID                        string `json:"ownerId"`
	SupportsAway                   bool   `json:"supportsAway"`
	UserType                       int    `json:"userType"`
	UsersCount                     int    `json:"usersCount"`
}

func GetLocations(token string) (APIWrappedResponse[[]Location], error) {
	return Get[APIWrappedResponse[[]Location]]("/Location", token)
}

func SetLocationAwayState(locationID string, away bool, token string) error {
	awayState := 0
	if away {
		awayState = 1
	}
	d, err := json.Marshal(map[string]any{
		"awayState": awayState,
	})
	if err != nil {
		return err
	}

	_, err = API[any]("PATCH", fmt.Sprintf("/Location/%v/State", url.PathEscape(locationID)), bytes.NewReader(d), http.StatusOK, false, token)
	return err
}

// SetDeviceTemperature sets both the heat and cool targets on a device.
//
// Both targets are always sent together, even when the caller only cares
// about one. Live testing against the Tekmar 5xx API showed that sending
// a single-field PATCH (e.g. {"Heat": 66}) in a single-direction mode
// (Heat or Cool) is accepted but silently corrupts the omitted setpoint —
// the server resets it to Schedule.HeatMin (Cool-only) or Schedule.CoolMax
// (Heat-only). Callers must pass the current value of the field they aren't
// changing; read it from a cached device state (see deviceState.Get).
//
// When a schedule is active, the API expects "HeatHold"/"CoolHold" keys
// instead of "Heat"/"Cool". This branching is unverified against the 5xx
// API (our capture ran with SchedEnable.Val="Off"); keep the existing
// behavior until proven wrong.
func SetDeviceTemperature(deviceID string, scheduleActive bool, heat, cool float64, token string) error {
	heatKey, coolKey := "Heat", "Cool"
	if scheduleActive {
		heatKey, coolKey = "HeatHold", "CoolHold"
	}

	d, err := json.Marshal(map[string]any{
		"Settings": map[string]any{
			heatKey: heat,
			coolKey: cool,
		},
	})
	if err != nil {
		return err
	}

	_, err = API[any]("PATCH", fmt.Sprintf("/Device/%v", url.PathEscape(deviceID)), bytes.NewReader(d), http.StatusOK, false, token)
	return err
}

func SetDeviceMode(deviceID, mode, token string) error {
	d, err := json.Marshal(map[string]any{
		"Settings": map[string]any{
			"Mode": mode,
		},
	})
	if err != nil {
		return err
	}

	_, err = API[any]("PATCH", fmt.Sprintf("/Device/%v", url.PathEscape(deviceID)), bytes.NewReader(d), http.StatusOK, false, token)
	return err
}

func SetDeviceFanMode(deviceID, fanMode, token string) error {
	d, err := json.Marshal(map[string]any{
		"Settings": map[string]any{
			"Fan": fanMode,
		},
	})
	if err != nil {
		return err
	}

	_, err = API[any]("PATCH", fmt.Sprintf("/Device/%v", url.PathEscape(deviceID)), bytes.NewReader(d), http.StatusOK, false, token)
	return err
}

// SetDeviceFloorMin writes both the occupied (W) and away (A) radiant floor
// minimums. Like SetDeviceTemperature, both fields are always sent — echo
// the current value of the field you aren't changing.
//
// Payload: {"Settings":{"Schedule":{"Floor":{"W":<w>,"A":<a>}}}}
//
// FloorMax is read-only in this API; no writable companion exists.
func SetDeviceFloorMin(deviceID string, w, a float64, token string) error {
	d, err := json.Marshal(map[string]any{
		"Settings": map[string]any{
			"Schedule": map[string]any{
				"Floor": map[string]any{
					"W": w,
					"A": a,
				},
			},
		},
	})
	if err != nil {
		return err
	}
	_, err = API[any]("PATCH", fmt.Sprintf("/Device/%v", url.PathEscape(deviceID)), bytes.NewReader(d), http.StatusOK, false, token)
	return err
}

// SetDeviceHumidity writes the humidifier target. Only meaningful when the
// device has Hum.Active == 1.
//
// Payload: {"Settings":{"Hum":<val>}}
func SetDeviceHumidity(deviceID string, target float64, token string) error {
	d, err := json.Marshal(map[string]any{
		"Settings": map[string]any{
			"Hum": target,
		},
	})
	if err != nil {
		return err
	}
	_, err = API[any]("PATCH", fmt.Sprintf("/Device/%v", url.PathEscape(deviceID)), bytes.NewReader(d), http.StatusOK, false, token)
	return err
}

type ScheduleSetting struct {
	// Cool to this temp
	C float64 `json:"C"`
	// Heat to this temp
	H float64 `json:"H"`
	// Time of event, ex, 07:00
	T string `json:"T"`
}

type ScheduleGroup struct {
	// Consists of one or more of the following characters:
	// - M: Monday
	// - T: Tuesday
	// - W: Wednesday
	// - R: Thursday
	// - F: Friday
	// - A: Saturday
	// - S: Sunday
	Days string `json:"Days"`
	// Wake
	W ScheduleSetting `json:"W"`
	// Leave
	L ScheduleSetting `json:"L"`
	// Return
	R ScheduleSetting `json:"R"`
	// Sleep
	S ScheduleSetting `json:"S"`
}

const SensorStatusAbsent = "Absent"
const SensorStatusOkay = "Okay"

type Sensor[T any] struct {
	Status string `json:"Status"`
	Value  T      `json:"Val"`
}

// This is the schema for a single type of device - my thermostat. Not sure about others.
type MyDevice struct {
	Data struct {
		DateTime time.Time `json:"DateTime"`
		Dehum    struct {
			Active int `json:"Active"`
			Max    int `json:"Max"`
			Min    int `json:"Min"`
			Steps  int `json:"Steps"`
			Val    int `json:"Val"`
		} `json:"Dehum"`
		Energy struct {
			Cool struct {
				Daily   []float64 `json:"Daily"`
				Monthly []float64 `json:"Monthly"`
			} `json:"Cool"`
			Heat struct {
				Daily   []float64 `json:"Daily"`
				Monthly []float64 `json:"Monthly"`
			} `json:"Heat"`
		} `json:"Energy"`
		Fan struct {
			Active int      `json:"Active"`
			Enum   []string `json:"Enum"`
			Relay  int      `json:"Relay"`
			Val    string   `json:"Val"`
		} `json:"Fan"`
		Hum struct {
			Active int `json:"Active"`
			Max    int `json:"Max"`
			Min    int `json:"Min"`
			Steps  int `json:"Steps"`
			Val    int `json:"Val"`
		} `json:"Hum"`
		HumInterlock int `json:"HumInterlock"`
		Mode         struct {
			Active int      `json:"Active"`
			Enum   []string `json:"Enum"`
			Val    string   `json:"Val"`
		} `json:"Mode"`
		OpenADR struct {
			Active int      `json:"Active"`
			Enum   []string `json:"Enum"`
			Val    string   `json:"Val"`
		} `json:"OpenADR"`
		SchedEnable struct {
			Active int      `json:"Active"`
			Enum   []string `json:"Enum"`
			Val    string   `json:"Val"`
		} `json:"SchedEnable"`
		Schedule struct {
			CoolActive  int           `json:"CoolActive"`
			CoolMax     float64       `json:"CoolMax"`
			CoolMin     float64       `json:"CoolMin"`
			Event       string        `json:"Event"`
			FloorActive int           `json:"FloorActive"`
			FloorMax    float64       `json:"FloorMax"` // read-only hardware limit
			FloorMin    float64       `json:"FloorMin"` // read-only hardware limit
			// Floor holds the user-facing radiant floor minimum setpoints. W is the
			// occupied minimum; A is the away/setback minimum. These are writable
			// via PATCH /Device/{id} with body:
			//   {"Settings":{"Schedule":{"Floor":{"W":<occupied>,"A":<away>}}}}
			// Distinct from FloorMin/FloorMax which are read-only hardware bounds.
			Floor struct {
				W float64 `json:"W"`
				A float64 `json:"A"`
			} `json:"Floor"`
			Grp         int           `json:"Grp"`
			Grp1        ScheduleGroup `json:"Grp1"`
			Grp2        ScheduleGroup `json:"Grp2"`
			Grp3        ScheduleGroup `json:"Grp3"`
			Grp4        ScheduleGroup `json:"Grp4"`
			Grp5        ScheduleGroup `json:"Grp5"`
			Grp6        ScheduleGroup `json:"Grp6"`
			Grp7        ScheduleGroup `json:"Grp7"`
			HeatActive  int           `json:"HeatActive"`
			HeatMax     float64       `json:"HeatMax"`
			HeatMin     float64       `json:"HeatMin"`
			SchedActive int           `json:"SchedActive"`
			TempSteps   float64       `json:"TempSteps"`
			TimeSteps   int           `json:"TimeSteps"`
		} `json:"Schedule"`
		Sensors struct {
			Floor   Sensor[float64] `json:"Floor"`
			Outdoor Sensor[float64] `json:"Outdoor"`
			Rh      Sensor[float64] `json:"RH"`
			Room    Sensor[float64] `json:"Room"`
		} `json:"Sensors"`
		State struct {
			// Known values: "Off"
			Op  string `json:"Op"`
			Sub string `json:"Sub"`
		} `json:"State"`
		TZOffset int `json:"TZOffset"`
		Target   struct {
			Active int     `json:"Active"`
			Cool   float64 `json:"Cool"`
			Heat   float64 `json:"Heat"`
			Hold   float64 `json:"Hold"`
			Max    float64 `json:"Max"`
			Min    float64 `json:"Min"`
			Sensor string  `json:"Sensor"`
			Steps  float64 `json:"Steps"`
		} `json:"Target"`
		TempInterlock float64 `json:"TempInterlock"`
		TempUnits     struct {
			Active int      `json:"Active"`
			Enum   []string `json:"Enum"`
			Val    string   `json:"Val"`
		} `json:"TempUnits"`
		Units string `json:"Units"`
	} `json:"data"`
	DeviceID     string `json:"deviceId"`
	DeviceType   string `json:"deviceType"`
	DeviceTypeID int    `json:"deviceTypeId"`
	ImageURL     any    `json:"imageUrl"`
	IsConnected  bool   `json:"isConnected"`
	IsShared     bool   `json:"isShared"`
	Location     struct {
		Address struct {
			Address       string `json:"address"`
			Address2      string `json:"address2"`
			City          string `json:"city"`
			Country       string `json:"country"`
			StateProvince string `json:"state_province"`
			Zipcode       string `json:"zipcode"`
		} `json:"address"`
		AwayState  int    `json:"awayState"`
		LocationID string `json:"locationId"`
		Name       string `json:"name"`
		UserType   int    `json:"userType"`
	} `json:"location"`
	ModelID        int    `json:"modelId"`
	ModelNumber    string `json:"modelNumber"`
	Name           string `json:"name"`
	RequestingUser string `json:"requestingUser"`
}

func GetDevices(locationID, token string) (APIWrappedResponse[[]MyDevice], error) {
	return Get[APIWrappedResponse[[]MyDevice]](fmt.Sprintf("/Location/%v/Devices", url.PathEscape(locationID)), token)
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func RefreshAuthToken(refreshToken string) (ExchangedAuthTokenResponse, error) {
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("scope", "https://wattsb2cap02.onmicrosoft.com/wattsapiresi/manage+offline_access+openid+profile")
	data.Set("client_info", "1")
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)

	req, err := http.NewRequest("POST", "https://login.watts.io/tfp/wattsb2cap02.onmicrosoft.com/B2C_1A_Residential_UnifiedSignUpOrSignIn/oauth2/v2.0/token?haschrome=1", strings.NewReader(strings.ReplaceAll(data.Encode(), "%2B", "+")))
	if err != nil {
		return ExchangedAuthTokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", browserUA)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ExchangedAuthTokenResponse{}, err
	}
	defer resp.Body.Close()

	if err := expect(req, resp, http.StatusOK); err != nil {
		return ExchangedAuthTokenResponse{}, err
	}

	var decoded ExchangedAuthTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return ExchangedAuthTokenResponse{}, err
	}

	return decoded, nil
}

func authenticate(username, pass, tokensPath string) ExchangedAuthTokenResponse {
	var tokens ExchangedAuthTokenResponse

	previousTokensData, err := os.ReadFile(tokensPath)

	if err != nil && !os.IsNotExist(err) {
		log.Fatalf("failed to read previous tokens: %v", err)
	}

	if err == nil {
		if err := json.Unmarshal(previousTokensData, &tokens); err != nil {
			log.Fatalf("failed to read old tokens file: %v", err)
		}
		log.Println("read old tokens")
		if tokens.ExpiresOn < int(time.Now().Add(time.Minute).Unix()) {
			log.Println("old tokens are expired, trying refresh")
			if tokens.RefreshToken != "" {
				refreshed, err := RefreshAuthToken(tokens.RefreshToken)
				if err != nil {
					log.Printf("refresh failed, will re-login: %v", err)
					tokens = ExchangedAuthTokenResponse{}
				} else {
					log.Println("refreshed tokens successfully")
					tokens = refreshed
					tokensMarshalled, _ := json.Marshal(tokens)
					os.WriteFile(tokensPath, tokensMarshalled, os.ModePerm)
				}
			} else {
				tokens = ExchangedAuthTokenResponse{}
			}
		}
	}

	if os.IsNotExist(err) || tokens.AccessToken == "" {
		verifier := NewCodeVerifier()
		code, err := LoginSelfAsserted(verifier, username, pass)
		if err != nil {
			log.Fatal(err)
		}
		tokens, err = ExchangeAuthToken(code, verifier)
		if err != nil {
			log.Fatal(err)
		}
		tokensMarshalled, _ := json.Marshal(tokens)
		os.WriteFile(tokensPath, tokensMarshalled, os.ModePerm)
		log.Println("new tokens")
	}

	return tokens
}

// wattsToHAMode maps Watts API mode values to Home Assistant HVAC modes.
func wattsToHAMode(wattsMode string) string {
	switch strings.ToLower(wattsMode) {
	case "heat":
		return "heat"
	case "cool":
		return "cool"
	case "auto", "heat-cool":
		return "heat_cool"
	case "off":
		return "off"
	case "fan":
		return "fan_only"
	case "dry", "dehumidify":
		return "dry"
	case "emer", "emergency":
		// Heat-pump emergency/aux heat. HA has no canonical HVAC mode
		// for this, but accepts arbitrary mode strings in the
		// hvac_modes list and renders the snake_case as title-case
		// ("Emergency heat") in the climate card.
		return "emergency_heat"
	default:
		return strings.ToLower(wattsMode)
	}
}

// haToWattsMode maps Home Assistant HVAC modes back to Watts API mode values.
func haToWattsMode(haMode string) string {
	switch haMode {
	case "heat":
		return "Heat"
	case "cool":
		return "Cool"
	case "heat_cool":
		return "Auto"
	case "off":
		return "Off"
	case "fan_only":
		return "Fan"
	case "dry":
		return "Dry"
	case "emergency_heat":
		return "Emer"
	default:
		return haMode
	}
}

// wattsToHAAction maps Watts operational state to HA HVAC action.
func wattsToHAAction(op string) string {
	switch strings.ToLower(op) {
	case "heat", "heating":
		return "heating"
	case "cool", "cooling":
		return "cooling"
	case "off":
		return "off"
	case "idle", "":
		return "idle"
	default:
		return "idle"
	}
}

func mqttTopicPrefix(deviceID string) string {
	return fmt.Sprintf("watts/%s", deviceID)
}

// publishDiscovery publishes MQTT Discovery configs for all entities
// attached to a thermostat. Requires the device to be online with a valid
// data block — an offline device has empty TempUnits.Val and zero bounds,
// which HA's MQTT discovery validator rejects. Callers should gate on
// device.IsConnected && device.Data.TempUnits.Val != "".
func publishDiscovery(client mqtt.Client, device MyDevice) {
	prefix := mqttTopicPrefix(device.DeviceID)

	// Map available modes from the device. Dedupe — Watts' "Heat" and
	// "Emer" are distinct modes (one is heat-pump, one is aux/emergency
	// heat) and both should show up in HA, but if any mapping collision
	// ever happened we don't want duplicate entries in hvac_modes.
	var haModes []string
	seen := map[string]bool{}
	for _, m := range device.Data.Mode.Enum {
		ha := wattsToHAMode(m)
		if seen[ha] {
			continue
		}
		seen[ha] = true
		haModes = append(haModes, ha)
	}
	// Ensure "off" is always present
	if !seen["off"] {
		haModes = append(haModes, "off")
	}

	// Check if heat_cool (dual setpoint) is supported
	hasDualSetpoint := false
	for _, m := range haModes {
		if m == "heat_cool" {
			hasDualSetpoint = true
			break
		}
	}

	config := map[string]any{
		// name: null so HA uses the device name as the entity name
		// instead of concatenating device.name + entity.name (which would
		// produce "Lower SouthWest Lower SouthWest").
		"name":                      nil,
		"unique_id":                 fmt.Sprintf("watts_%s", device.DeviceID),
		"mode_command_topic":        prefix + "/mode/set",
		"mode_state_topic":          prefix + "/mode/state",
		"current_temperature_topic": prefix + "/current_temp",
		"action_topic":              prefix + "/action",
		"availability_topic":        prefix + "/availability",
		"modes":                     haModes,
		"min_temp":                  device.Data.Target.Min,
		"max_temp":                  device.Data.Target.Max,
		"temp_step":                 device.Data.Target.Steps,
		"temperature_unit":          device.Data.TempUnits.Val,
		"optimistic":                true,
		"device": map[string]any{
			"identifiers":  []string{fmt.Sprintf("watts_%s", device.DeviceID)},
			"name":         device.Name,
			"manufacturer": "Watts",
			"model":        device.ModelNumber,
		},
	}

	// Temperature command topics
	config["temperature_command_topic"] = prefix + "/temp/set"
	config["temperature_state_topic"] = prefix + "/temp/state"

	if hasDualSetpoint {
		config["temperature_high_command_topic"] = prefix + "/temp_high/set"
		config["temperature_high_state_topic"] = prefix + "/temp_high/state"
		config["temperature_low_command_topic"] = prefix + "/temp_low/set"
		config["temperature_low_state_topic"] = prefix + "/temp_low/state"
	}

	if len(device.Data.Fan.Enum) > 0 {
		config["fan_mode_command_topic"] = prefix + "/fan/set"
		config["fan_mode_state_topic"] = prefix + "/fan/state"
		config["fan_modes"] = device.Data.Fan.Enum
	}

	if device.Data.Sensors.Rh.Status == SensorStatusOkay {
		config["current_humidity_topic"] = prefix + "/current_humidity"
	}

	payload, _ := json.Marshal(config)
	discoveryTopic := fmt.Sprintf("homeassistant/climate/watts_%s/config", device.DeviceID)

	token := client.Publish(discoveryTopic, 1, true, payload)
	token.Wait()
	if token.Error() != nil {
		log.Printf("failed to publish discovery for %s: %v", device.DeviceID, token.Error())
	} else {
		log.Printf("published discovery config for %s on %s", device.Name, discoveryTopic)
	}

	// Outdoor temperature sensor
	if device.Data.Sensors.Outdoor.Status == SensorStatusOkay {
		publishTemperatureSensorDiscovery(client, device, "outdoor_temp", "Outdoor Temperature")
	}

	// Floor temperature sensor (only on radiant-floor rooms).
	if device.Data.Sensors.Floor.Status == SensorStatusOkay {
		publishTemperatureSensorDiscovery(client, device, "floor_temp", "Floor Temperature")

		// Radiant-only heating detection. On a device with a floor sensor
		// installed, State.Op=="Heat" AND Fan.Relay==0 means the radiant
		// loop is calling without the air handler (forced-air heat would
		// engage Fan.Relay). Not a perfect signal for mixed radiant+air
		// rooms — if both are running, the fan is on and the radiant call
		// is hidden — but for radiant-only rooms it's exact.
		publishBinarySensorDiscovery(client, device, "radiant_heating", "Radiant Heating", "heat", "")

		// Floor heating climate entity. The Watts API exposes two
		// conceptually different "floor" values:
		//
		//   Schedule.Floor.W      — user-writable occupied floor
		//                           minimum. Setting this raises the
		//                           floor if it drops below W. This
		//                           maps to the climate's target
		//                           temperature (the "setpoint").
		//   Schedule.FloorMin     — read-only hardware floor lower
		//                           bound (the thermostat's absolute
		//                           minimum capability).
		//   Schedule.FloorMax     — read-only hardware safety ceiling,
		//                           typically installer-set for the
		//                           flooring material (e.g., hardwood
		//                           protection). Maps to max_temp on
		//                           the climate entity's slider.
		//
		// Modeled as a single-mode "heat" climate. HA requires at least
		// one HVAC mode; the Watts API has no separate floor on/off
		// (setting the setpoint to 0 is how you disable it), so we
		// accept the mode_command topic and no-op on it. min_temp is 0
		// to allow that "disabled" sentinel through the slider.
		floorCfg := map[string]any{
			"name":                      "Floor",
			"unique_id":                 fmt.Sprintf("watts_%s_floor", device.DeviceID),
			"current_temperature_topic": prefix + "/floor_temp",
			"temperature_state_topic":   prefix + "/floor_target",
			"temperature_command_topic": prefix + "/floor_target/set",
			"mode_state_topic":          prefix + "/floor_mode",
			"mode_command_topic":        prefix + "/floor_mode/set",
			"action_topic":              prefix + "/floor_action",
			"availability_topic":        prefix + "/availability",
			"modes":                     []string{"heat"},
			"min_temp":                  0,
			"max_temp":                  device.Data.Schedule.FloorMax,
			"temp_step":                 1,
			"temperature_unit":          device.Data.TempUnits.Val,
			"optimistic":                false,
			"device":                    haDeviceBlock(device),
		}
		publishDiscoveryConfig(client, "climate",
			fmt.Sprintf("watts_%s_floor", device.DeviceID), floorCfg)

		// Floor Max diagnostic sensor — same value visible as max_temp
		// on the climate entity's slider, but also surfaced as a
		// standalone sensor so it can be shown as a numeric readout in
		// dashboards / graphed / used in templates.
		floorMaxCfg := map[string]any{
			"name":                "Floor Max",
			"unique_id":           fmt.Sprintf("watts_%s_floor_max", device.DeviceID),
			"state_topic":         prefix + "/floor_max",
			"availability_topic":  prefix + "/availability",
			"device_class":        "temperature",
			"state_class":         "measurement",
			"unit_of_measurement": "°" + device.Data.TempUnits.Val,
			"entity_category":     "diagnostic",
			"icon":                "mdi:thermometer-chevron-up",
			"device":              haDeviceBlock(device),
		}
		publishDiscoveryConfig(client, "sensor",
			fmt.Sprintf("watts_%s_floor_max", device.DeviceID), floorMaxCfg)
	}

	// Fan running binary sensor (Fan.Relay == 1 means the fan motor is
	// physically engaged; this is the only runtime relay the API exposes
	// and is the closest thing to a "humidifier running" signal for rooms
	// with a humidifier that drives the air handler).
	if device.Data.Fan.Active == 1 {
		publishBinarySensorDiscovery(client, device, "fan_running", "Fan Running", "running", "")
	}

	// Humidifier entity (only on rooms with a humidifier accessory).
	//
	// The Watts API has no explicit humidifier on/off: the accessory runs
	// whenever current RH is below target. HA's humidifier MQTT schema
	// requires an on/off command_topic + state_topic; we publish state=ON
	// unconditionally and silently ignore OFF commands. With
	// optimistic=false, HA waits for the state_topic to confirm a change
	// before moving the toggle — since we never publish OFF, the toggle
	// won't move and the user-visible effect is "the humidifier is always
	// on, only the target changes things."
	//
	// Modes are intentionally omitted: HA's modes list is an inclusion
	// group with mode_command_topic / mode_state_topic, and we have no
	// real modes to expose.
	if device.Data.Hum.Active == 1 {
		humCfg := map[string]any{
			"name":                          "Humidifier",
			"unique_id":                     fmt.Sprintf("watts_%s_humidifier", device.DeviceID),
			"device_class":                  "humidifier",
			"command_topic":                 prefix + "/humidifier/set",
			"state_topic":                   prefix + "/humidifier/state",
			"target_humidity_command_topic": prefix + "/humidifier/target/set",
			"target_humidity_state_topic":   prefix + "/humidifier/target",
			"current_humidity_topic":        prefix + "/current_humidity",
			"action_topic":                  prefix + "/humidifier/action",
			"availability_topic":            prefix + "/availability",
			"min_humidity":                  device.Data.Hum.Min,
			"max_humidity":                  device.Data.Hum.Max,
			"payload_on":                    "ON",
			"payload_off":                   "OFF",
			// optimistic: false so HA waits for state_topic confirmation
			// before moving the on/off toggle. We never publish OFF, so
			// the toggle can't be clicked off.
			"optimistic": false,
			"device":     haDeviceBlock(device),
		}
		publishDiscoveryConfig(client, "humidifier",
			fmt.Sprintf("watts_%s_humidifier", device.DeviceID), humCfg)

		// Runtime binary sensor for "the humidifier is engaged right now"
		// — kept separate from the humidifier.action topic so it's
		// addressable in automations as a first-class entity.
		publishBinarySensorDiscovery(client, device, "humidifier_running",
			"Humidifier Running", "running", "")
	}

	// Cold Weather Shutdown diagnostic — lights up when State.Sub=="CWSD"
	// (heat-pump cooling locked out due to outdoor temp below the
	// compressor's safe operating range). Helps explain why a room with a
	// cool call isn't actually cooling.
	publishBinarySensorDiscovery(client, device, "cold_weather_shutdown",
		"Cold Weather Shutdown", "problem", "diagnostic")

	// Daily energy sensors (today's heat/cool consumption in kWh).
	// Energy.Heat.Daily / Energy.Cool.Daily each carry the last 7 days
	// (oldest first); the last element is today's running total.
	publishEnergySensorDiscovery(client, device, "energy_heat_today", "Heat Today")
	publishEnergySensorDiscovery(client, device, "energy_cool_today", "Cool Today")
}

// publishEnergySensorDiscovery publishes an energy sensor (kWh, daily).
// Uses state_class: total_increasing which tolerates the daily reset to 0.
func publishEnergySensorDiscovery(client mqtt.Client, device MyDevice, key, name string) {
	prefix := mqttTopicPrefix(device.DeviceID)
	cfg := map[string]any{
		"name":                name,
		"unique_id":           fmt.Sprintf("watts_%s_%s", device.DeviceID, key),
		"state_topic":         prefix + "/" + key,
		"availability_topic":  prefix + "/availability",
		"device_class":        "energy",
		"state_class":         "total_increasing",
		"unit_of_measurement": "kWh",
		"device":              haDeviceBlock(device),
	}
	publishDiscoveryConfig(client, "sensor",
		fmt.Sprintf("watts_%s_%s", device.DeviceID, key), cfg)
}

// publishTemperatureSensorDiscovery publishes MQTT Discovery for a
// temperature sensor attached to a thermostat.
func publishTemperatureSensorDiscovery(client mqtt.Client, device MyDevice, key, name string) {
	prefix := mqttTopicPrefix(device.DeviceID)
	cfg := map[string]any{
		"name":                name,
		"unique_id":           fmt.Sprintf("watts_%s_%s", device.DeviceID, key),
		"state_topic":         prefix + "/" + key,
		"availability_topic":  prefix + "/availability",
		"device_class":        "temperature",
		"state_class":         "measurement",
		"unit_of_measurement": "°" + device.Data.TempUnits.Val,
		"device":              haDeviceBlock(device),
	}
	publishDiscoveryConfig(client, "sensor",
		fmt.Sprintf("watts_%s_%s", device.DeviceID, key), cfg)
}

// haDeviceBlock returns the standard device metadata block used by every
// MQTT Discovery payload so entities on the same thermostat group together
// in the HA UI.
func haDeviceBlock(device MyDevice) map[string]any {
	return map[string]any{
		"identifiers":  []string{fmt.Sprintf("watts_%s", device.DeviceID)},
		"name":         device.Name,
		"manufacturer": "Watts",
		"model":        device.ModelNumber,
	}
}

// publishDiscoveryConfig publishes a single MQTT Discovery config payload
// to homeassistant/<component>/<object_id>/config.
func publishDiscoveryConfig(client mqtt.Client, component, objectID string, config map[string]any) {
	payload, _ := json.Marshal(config)
	topic := fmt.Sprintf("homeassistant/%s/%s/config", component, objectID)
	t := client.Publish(topic, 1, true, payload)
	t.Wait()
	if t.Error() != nil {
		log.Printf("failed to publish discovery %s: %v", topic, t.Error())
	}
}

// publishBinarySensorDiscovery publishes MQTT Discovery for a binary_sensor
// entity attached to a thermostat. key is the object suffix (e.g.
// "fan_running"); name is the human-readable label; deviceClass is HA's
// binary_sensor device_class (empty string to omit); entityCategory is HA's
// entity_category (e.g. "diagnostic") or empty to omit.
func publishBinarySensorDiscovery(client mqtt.Client, device MyDevice, key, name, deviceClass, entityCategory string) {
	prefix := mqttTopicPrefix(device.DeviceID)
	cfg := map[string]any{
		"name":               name,
		"unique_id":          fmt.Sprintf("watts_%s_%s", device.DeviceID, key),
		"state_topic":        prefix + "/" + key,
		"availability_topic": prefix + "/availability",
		"payload_on":         "ON",
		"payload_off":        "OFF",
		"device":             haDeviceBlock(device),
	}
	if deviceClass != "" {
		cfg["device_class"] = deviceClass
	}
	if entityCategory != "" {
		cfg["entity_category"] = entityCategory
	}
	publishDiscoveryConfig(client, "binary_sensor",
		fmt.Sprintf("watts_%s_%s", device.DeviceID, key), cfg)
}

func publishState(client mqtt.Client, device MyDevice) {
	prefix := mqttTopicPrefix(device.DeviceID)

	pub := func(topic, value string) {
		t := client.Publish(prefix+"/"+topic, 0, true, value)
		t.Wait()
	}

	// Availability
	if device.IsConnected {
		pub("availability", "online")
	} else {
		pub("availability", "offline")
	}

	// Current temperature
	if device.Data.Sensors.Room.Status == SensorStatusOkay {
		pub("current_temp", fmt.Sprintf("%.1f", device.Data.Sensors.Room.Value))
	}

	// Current humidity
	if device.Data.Sensors.Rh.Status == SensorStatusOkay {
		pub("current_humidity", fmt.Sprintf("%.1f", device.Data.Sensors.Rh.Value))
	}

	// Mode
	haMode := wattsToHAMode(device.Data.Mode.Val)
	pub("mode/state", haMode)

	// Target temperatures. Always publish all three state topics from the
	// latest Target.Heat/Target.Cool (the Watts API returns both even in
	// single-direction modes), so HA never sees stale values carried over
	// from a previous mode. The single `temp/state` tracks whichever
	// setpoint is meaningful for the current mode; in heat_cool it stays
	// equal to the heat target (HA's card consults target_temp_high/low
	// in that mode anyway).
	pub("temp_high/state", fmt.Sprintf("%.1f", device.Data.Target.Cool))
	pub("temp_low/state", fmt.Sprintf("%.1f", device.Data.Target.Heat))
	switch haMode {
	case "cool":
		pub("temp/state", fmt.Sprintf("%.1f", device.Data.Target.Cool))
	default:
		// heat / heat_cool / emergency_heat / off — heat setpoint is
		// the sensible single-target fallback
		pub("temp/state", fmt.Sprintf("%.1f", device.Data.Target.Heat))
	}

	// Outdoor temperature
	if device.Data.Sensors.Outdoor.Status == SensorStatusOkay {
		pub("outdoor_temp", fmt.Sprintf("%.1f", device.Data.Sensors.Outdoor.Value))
	}

	// Fan mode
	if device.Data.Fan.Val != "" {
		pub("fan/state", device.Data.Fan.Val)
	}

	// Fan running (physical relay state — the only runtime relay exposed
	// by the API). Flips to ON during heat/cool calls that engage the air
	// handler, and also during humidifier cycles (whole-home humidifiers
	// drive the fan). In a room where heat is pure-radiant, this stays OFF
	// even while State.Op == "Heat".
	if device.Data.Fan.Active == 1 {
		pub("fan_running", boolToOnOff(device.Data.Fan.Relay == 1))
	}

	// Floor heating entities on radiant-floor rooms.
	if device.Data.Sensors.Floor.Status == SensorStatusOkay {
		pub("floor_temp", fmt.Sprintf("%.1f", device.Data.Sensors.Floor.Value))

		// Radiant-heating detector. The Watts API does NOT surface
		// floor-only heat calls — State.Op reflects the thermostat's
		// ROOM heat call (Target.Heat vs Room), not the floor's
		// (Schedule.Floor.W vs Sensors.Floor.Val). Floor-only calls are
		// handled locally by the Tekmar 563 and never reach the cloud.
		//
		// We infer instead: when the floor setpoint is enabled and the
		// floor temperature is below it, the system should be calling
		// for floor heat (modulo the thermostat's local hysteresis).
		// This is an imperfect signal (may false-positive during the
		// hysteresis deadband) but strictly more useful than always-idle.
		floorTarget := device.Data.Schedule.Floor.W
		floorTemp := device.Data.Sensors.Floor.Value
		radiantCalling := floorTarget > 0 && floorTemp < floorTarget
		pub("radiant_heating", boolToOnOff(radiantCalling))

		// Floor climate entity state topics.
		pub("floor_target", fmt.Sprintf("%.0f", floorTarget))
		pub("floor_mode", "heat")
		floorAction := "idle"
		if radiantCalling {
			floorAction = "heating"
		}
		pub("floor_action", floorAction)

		// Floor Max diagnostic sensor state.
		pub("floor_max", fmt.Sprintf("%.0f", device.Data.Schedule.FloorMax))
	}

	// Cold Weather Shutdown diagnostic (always published, not gated).
	pub("cold_weather_shutdown", boolToOnOff(device.Data.State.Sub == "CWSD"))

	// Humidifier state (only on rooms with a humidifier accessory).
	// Runtime heuristic: whole-home humidifiers drive the air-handler
	// fan to distribute moisture. On a room where the humidifier is
	// installed, Fan.Relay==1 AND State.Op=="Off" means the humidifier
	// is the likely reason — no heat/cool call to explain the fan. Not
	// perfect (the API provides no dedicated humidifier-running flag)
	// but it's the best signal available.
	if device.Data.Hum.Active == 1 {
		// Fixed ON — the Watts humidifier has no user-facing disable,
		// so the HA humidifier entity's on/off stays pinned to ON.
		pub("humidifier/state", "ON")
		pub("humidifier/target", fmt.Sprintf("%d", device.Data.Hum.Val))

		humidifying := device.Data.Fan.Relay == 1 && device.Data.State.Op == "Off"
		humAction := "idle"
		if humidifying {
			humAction = "humidifying"
		}
		pub("humidifier/action", humAction)
		pub("humidifier_running", boolToOnOff(humidifying))
	}

	// Action (what the system is currently doing)
	pub("action", wattsToHAAction(device.Data.State.Op))

	// Daily energy — last element of the 7-day array is today's total.
	if len(device.Data.Energy.Heat.Daily) > 0 {
		pub("energy_heat_today", fmt.Sprintf("%.2f",
			device.Data.Energy.Heat.Daily[len(device.Data.Energy.Heat.Daily)-1]))
	}
	if len(device.Data.Energy.Cool.Daily) > 0 {
		pub("energy_cool_today", fmt.Sprintf("%.2f",
			device.Data.Energy.Cool.Daily[len(device.Data.Energy.Cool.Daily)-1]))
	}
}

// boolToOnOff converts a Go bool to the MQTT ON/OFF string convention
// used by binary_sensor entities.
func boolToOnOff(on bool) string {
	if on {
		return "ON"
	}
	return "OFF"
}

// deviceState tracks the latest known state of each device so command
// handlers can determine whether a schedule is active.
type deviceState struct {
	mu       sync.RWMutex
	devices  map[string]MyDevice      // keyed by deviceID
	expected map[string]expectedWrite // keyed by deviceID — pending writes awaiting confirmation via poll
}

// expectedWrite holds per-field values the user wrote that we haven't
// yet seen echoed in a poll response. The cloud's read API lags writes
// by a variable amount (5 s – 60 s+ in practice); we keep publishing
// the user's intent until a poll confirms it, then clear the entry.
// Abandoned after expectedAbandonAfter to avoid pinning forever if the
// cloud silently refuses a write.
type expectedWrite struct {
	heat, cool     *float64
	floorW, floorA *float64
	humVal         *int
	mode, fan      *string
	ts             time.Time
}

const expectedAbandonAfter = 5 * time.Minute

func (ds *deviceState) Update(devices []MyDevice) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	for _, d := range devices {
		ds.devices[d.DeviceID] = d
	}
}

func (ds *deviceState) Get(deviceID string) (MyDevice, bool) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	d, ok := ds.devices[deviceID]
	return d, ok
}

// Mutate runs the given mutator on the cached MyDevice for deviceID.
// Used by command handlers to keep the cache consistent so that echoed
// values in subsequent writes (e.g., sending both Heat and Cool each
// time) see fresh data rather than stale values from the previous poll.
// Does NOT by itself affect the poll-confirmation logic — call Expect()
// separately for that.
func (ds *deviceState) Mutate(deviceID string, mutator func(*MyDevice)) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if d, ok := ds.devices[deviceID]; ok {
		mutator(&d)
		ds.devices[deviceID] = d
	}
}

// Expect records what the user just wrote so the poll loop can override
// stale polled values with the user's intent until the cloud catches up.
// Each call merges into any existing pending expectation (later writes
// supersede earlier ones field-by-field). The timestamp is refreshed so
// each new write resets the abandonment timer.
func (ds *deviceState) Expect(deviceID string, mutator func(*expectedWrite)) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	e := ds.expected[deviceID]
	mutator(&e)
	e.ts = time.Now()
	ds.expected[deviceID] = e
}

// MergeExpected overlays pending-write values onto a freshly-polled
// device and, for each field, clears the expectation if the poll confirms
// our written value. The returned device reflects our intent for
// unconfirmed fields and the poll for everything else. Entries older
// than expectedAbandonAfter are dropped (the cloud silently rejected a
// write, or an external change on the thermostat itself superseded us).
// Runtime fields (State.Op, Fan.Relay, sensor readings, energy) always
// come from the poll.
func (ds *deviceState) MergeExpected(polled MyDevice) MyDevice {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	e, ok := ds.expected[polled.DeviceID]
	if !ok {
		return polled
	}
	if time.Since(e.ts) > expectedAbandonAfter {
		delete(ds.expected, polled.DeviceID)
		return polled
	}
	if e.heat != nil {
		if polled.Data.Target.Heat == *e.heat {
			e.heat = nil
		} else {
			polled.Data.Target.Heat = *e.heat
		}
	}
	if e.cool != nil {
		if polled.Data.Target.Cool == *e.cool {
			e.cool = nil
		} else {
			polled.Data.Target.Cool = *e.cool
		}
	}
	if e.floorW != nil {
		if polled.Data.Schedule.Floor.W == *e.floorW {
			e.floorW = nil
		} else {
			polled.Data.Schedule.Floor.W = *e.floorW
		}
	}
	if e.floorA != nil {
		if polled.Data.Schedule.Floor.A == *e.floorA {
			e.floorA = nil
		} else {
			polled.Data.Schedule.Floor.A = *e.floorA
		}
	}
	if e.humVal != nil {
		if polled.Data.Hum.Val == *e.humVal {
			e.humVal = nil
		} else {
			polled.Data.Hum.Val = *e.humVal
		}
	}
	if e.mode != nil {
		if strings.EqualFold(polled.Data.Mode.Val, *e.mode) {
			e.mode = nil
		} else {
			polled.Data.Mode.Val = *e.mode
		}
	}
	if e.fan != nil {
		if polled.Data.Fan.Val == *e.fan {
			e.fan = nil
		} else {
			polled.Data.Fan.Val = *e.fan
		}
	}
	if e.heat == nil && e.cool == nil && e.floorW == nil && e.floorA == nil &&
		e.humVal == nil && e.mode == nil && e.fan == nil {
		delete(ds.expected, polled.DeviceID)
	} else {
		ds.expected[polled.DeviceID] = e
	}
	return polled
}

// publishDeviceFromCache publishes MQTT state for a single device using
// the latest cached values. Called from command handlers immediately
// after Mutate+Expect so HA sees the user's change in milliseconds — a
// race-free alternative to waiting on the pubSync→doSync cycle, which
// can lag by 5 s (post-write /Refresh sleep) plus any time the ticker
// consumes first with a stale poll.
func publishDeviceFromCache(client mqtt.Client, ds *deviceState, deviceID string) {
	if d, ok := ds.Get(deviceID); ok {
		publishState(client, d)
	}
}

func (ds *deviceState) IsScheduleActive(deviceID string) bool {
	d, ok := ds.Get(deviceID)
	if !ok {
		return false
	}
	return strings.ToLower(d.Data.SchedEnable.Val) == "on" || strings.ToLower(d.Data.SchedEnable.Val) == "enabled"
}

func subscribeCommands(client mqtt.Client, device MyDevice, state *deviceState, tokens *ExchangedAuthTokenResponse, username, pass, tokensPath string, tokensMu *sync.Mutex, pubSync chan string) {
	prefix := mqttTopicPrefix(device.DeviceID)
	deviceID := device.DeviceID

	getToken := func() string {
		tokensMu.Lock()
		defer tokensMu.Unlock()
		if tokens.ExpiresOn < int(time.Now().Add(2*time.Minute).Unix()) {
			*tokens = authenticate(username, pass, tokensPath)
		}
		return tokens.AccessToken
	}

	// Single setpoint (used in heat-only or cool-only modes). The API requires
	// BOTH Heat and Cool in every PATCH; we echo the current non-changing value.
	client.Subscribe(prefix+"/temp/set", 1, func(_ mqtt.Client, msg mqtt.Message) {
		val, err := strconv.ParseFloat(string(msg.Payload()), 64)
		if err != nil {
			log.Printf("invalid temp value: %s", msg.Payload())
			return
		}
		dev, ok := state.Get(deviceID)
		if !ok {
			log.Printf("no known state for device %s", deviceID)
			return
		}
		schedActive := state.IsScheduleActive(deviceID)
		haMode := wattsToHAMode(dev.Data.Mode.Val)

		heat, cool := dev.Data.Target.Heat, dev.Data.Target.Cool
		switch haMode {
		case "cool":
			cool = val
		default:
			heat = val
		}

		log.Printf("setting temp on %s: heat=%.1f cool=%.1f (schedule=%v)", deviceID, heat, cool, schedActive)
		if err := SetDeviceTemperature(deviceID, schedActive, heat, cool, getToken()); err != nil {
			log.Printf("failed to set temp on %s: %v", deviceID, err)
			return
		}
		state.Mutate(deviceID, func(d *MyDevice) {
			d.Data.Target.Heat = heat
			d.Data.Target.Cool = cool
		})
		h, c := heat, cool
		state.Expect(deviceID, func(e *expectedWrite) { e.heat, e.cool = &h, &c })
		publishDeviceFromCache(client, state, deviceID)
		pubSync <- deviceID
	})

	// Dual setpoint: high (cool target). Echo current Heat so it isn't reset.
	client.Subscribe(prefix+"/temp_high/set", 1, func(_ mqtt.Client, msg mqtt.Message) {
		val, err := strconv.ParseFloat(string(msg.Payload()), 64)
		if err != nil {
			log.Printf("invalid temp_high value: %s", msg.Payload())
			return
		}
		dev, ok := state.Get(deviceID)
		if !ok {
			log.Printf("no known state for device %s", deviceID)
			return
		}
		schedActive := state.IsScheduleActive(deviceID)
		log.Printf("setting cool target on %s: %.1f (schedule=%v)", deviceID, val, schedActive)
		if err := SetDeviceTemperature(deviceID, schedActive, dev.Data.Target.Heat, val, getToken()); err != nil {
			log.Printf("failed to set cool target on %s: %v", deviceID, err)
			return
		}
		v := val
		state.Mutate(deviceID, func(d *MyDevice) { d.Data.Target.Cool = v })
		state.Expect(deviceID, func(e *expectedWrite) { e.cool = &v })
		publishDeviceFromCache(client, state, deviceID)
		pubSync <- deviceID
	})

	// Dual setpoint: low (heat target). Echo current Cool so it isn't reset.
	client.Subscribe(prefix+"/temp_low/set", 1, func(_ mqtt.Client, msg mqtt.Message) {
		val, err := strconv.ParseFloat(string(msg.Payload()), 64)
		if err != nil {
			log.Printf("invalid temp_low value: %s", msg.Payload())
			return
		}
		dev, ok := state.Get(deviceID)
		if !ok {
			log.Printf("no known state for device %s", deviceID)
			return
		}
		schedActive := state.IsScheduleActive(deviceID)
		log.Printf("setting heat target on %s: %.1f (schedule=%v)", deviceID, val, schedActive)
		if err := SetDeviceTemperature(deviceID, schedActive, val, dev.Data.Target.Cool, getToken()); err != nil {
			log.Printf("failed to set heat target on %s: %v", deviceID, err)
			return
		}
		v := val
		state.Mutate(deviceID, func(d *MyDevice) { d.Data.Target.Heat = v })
		state.Expect(deviceID, func(e *expectedWrite) { e.heat = &v })
		publishDeviceFromCache(client, state, deviceID)
		pubSync <- deviceID
	})

	// Mode
	client.Subscribe(prefix+"/mode/set", 1, func(_ mqtt.Client, msg mqtt.Message) {
		haMode := string(msg.Payload())
		wattsMode := haToWattsMode(haMode)
		log.Printf("setting mode on %s: %s (watts: %s)", deviceID, haMode, wattsMode)
		if err := SetDeviceMode(deviceID, wattsMode, getToken()); err != nil {
			log.Printf("failed to set mode on %s: %v", deviceID, err)
			return
		}
		m := wattsMode
		state.Mutate(deviceID, func(d *MyDevice) { d.Data.Mode.Val = m })
		state.Expect(deviceID, func(e *expectedWrite) { e.mode = &m })
		publishDeviceFromCache(client, state, deviceID)
		pubSync <- deviceID
	})

	// Fan mode
	client.Subscribe(prefix+"/fan/set", 1, func(_ mqtt.Client, msg mqtt.Message) {
		fanMode := string(msg.Payload())
		log.Printf("setting fan mode on %s: %s", deviceID, fanMode)
		if err := SetDeviceFanMode(deviceID, fanMode, getToken()); err != nil {
			log.Printf("failed to set fan mode on %s: %v", deviceID, err)
			return
		}
		f := fanMode
		state.Mutate(deviceID, func(d *MyDevice) { d.Data.Fan.Val = f })
		state.Expect(deviceID, func(e *expectedWrite) { e.fan = &f })
		publishDeviceFromCache(client, state, deviceID)
		pubSync <- deviceID
	})

	// Floor climate target (Schedule.Floor.W — the user-facing occupied
	// floor minimum). Echoes current Away (A) so it isn't reset by the
	// server's both-fields requirement.
	client.Subscribe(prefix+"/floor_target/set", 1, func(_ mqtt.Client, msg mqtt.Message) {
		val, err := strconv.ParseFloat(string(msg.Payload()), 64)
		if err != nil {
			log.Printf("invalid floor target value: %s", msg.Payload())
			return
		}
		dev, ok := state.Get(deviceID)
		if !ok {
			log.Printf("no known state for device %s", deviceID)
			return
		}
		log.Printf("setting floor target on %s: W=%.1f (A=%.1f unchanged)",
			deviceID, val, dev.Data.Schedule.Floor.A)
		if err := SetDeviceFloorMin(deviceID, val, dev.Data.Schedule.Floor.A, getToken()); err != nil {
			log.Printf("failed to set floor target on %s: %v", deviceID, err)
			return
		}
		w, a := val, dev.Data.Schedule.Floor.A
		state.Mutate(deviceID, func(d *MyDevice) { d.Data.Schedule.Floor.W = w })
		state.Expect(deviceID, func(e *expectedWrite) { e.floorW, e.floorA = &w, &a })
		publishDeviceFromCache(client, state, deviceID)
		pubSync <- deviceID
	})

	// Floor climate mode — only "heat" is supported; the Watts API has
	// no separate floor on/off (target=0 is how you "disable" it). Accept
	// the command to satisfy HA's climate schema but no-op.
	client.Subscribe(prefix+"/floor_mode/set", 1, func(_ mqtt.Client, msg mqtt.Message) {
		log.Printf("floor_mode on %s: %q (no-op; drag target to 0 to disable)",
			deviceID, string(msg.Payload()))
	})

	// Humidifier target humidity (from the humidifier entity's
	// target_humidity_command_topic).
	client.Subscribe(prefix+"/humidifier/target/set", 1, func(_ mqtt.Client, msg mqtt.Message) {
		val, err := strconv.ParseFloat(string(msg.Payload()), 64)
		if err != nil {
			log.Printf("invalid humidity target: %s", msg.Payload())
			return
		}
		log.Printf("setting humidity target on %s: %.0f", deviceID, val)
		if err := SetDeviceHumidity(deviceID, val, getToken()); err != nil {
			log.Printf("failed to set humidity target on %s: %v", deviceID, err)
			return
		}
		iv := int(val)
		state.Mutate(deviceID, func(d *MyDevice) { d.Data.Hum.Val = iv })
		state.Expect(deviceID, func(e *expectedWrite) { e.humVal = &iv })
		publishDeviceFromCache(client, state, deviceID)
		pubSync <- deviceID
	})

	// Humidifier on/off command. The Watts API has no explicit enable
	// flag, so we silently accept and ignore both ON and OFF — the
	// entity's state_topic stays pinned to ON and (with
	// optimistic=false) HA's toggle won't move. Logged for debugging.
	client.Subscribe(prefix+"/humidifier/set", 1, func(_ mqtt.Client, msg mqtt.Message) {
		cmd := string(msg.Payload())
		log.Printf("humidifier %s on %s: no-op (Watts API has no explicit enable; entity pinned ON)",
			cmd, deviceID)
	})
}

// locationTopicPrefix is the MQTT topic root for location-scoped state
// (away switch, etc.). Distinct from per-device prefixes.
func locationTopicPrefix(locationID string) string {
	return fmt.Sprintf("watts/location/%s", locationID)
}

// publishLocationDiscovery publishes the MQTT Discovery config for a
// location-scoped switch.away.
func publishLocationDiscovery(client mqtt.Client, loc Location) {
	if !loc.SupportsAway {
		return
	}
	prefix := locationTopicPrefix(loc.LocationID)
	cfg := map[string]any{
		"name":               "Away",
		"unique_id":          fmt.Sprintf("watts_location_%s_away", loc.LocationID),
		"command_topic":      prefix + "/away/set",
		"state_topic":        prefix + "/away/state",
		"availability_topic": prefix + "/availability",
		"payload_on":         "ON",
		"payload_off":        "OFF",
		"device": map[string]any{
			"identifiers":  []string{fmt.Sprintf("watts_location_%s", loc.LocationID)},
			"name":         loc.Name,
			"manufacturer": "Watts",
			"model":        "Location",
		},
	}
	publishDiscoveryConfig(client, "switch",
		fmt.Sprintf("watts_location_%s_away", loc.LocationID), cfg)
}

// subscribeLocationCommands wires the away/set topic to the Watts API.
// Call once per location at startup.
func subscribeLocationCommands(client mqtt.Client, loc Location, tokens *ExchangedAuthTokenResponse, username, pass, tokensPath string, tokensMu *sync.Mutex, pubSync chan string) {
	if !loc.SupportsAway {
		return
	}
	prefix := locationTopicPrefix(loc.LocationID)
	getToken := func() string {
		tokensMu.Lock()
		defer tokensMu.Unlock()
		if tokens.ExpiresOn < int(time.Now().Add(2*time.Minute).Unix()) {
			*tokens = authenticate(username, pass, tokensPath)
		}
		return tokens.AccessToken
	}
	client.Subscribe(prefix+"/away/set", 1, func(_ mqtt.Client, msg mqtt.Message) {
		cmd := string(msg.Payload())
		away := cmd == "ON"
		log.Printf("setting away state on location %s: %v", loc.LocationID, away)
		if err := SetLocationAwayState(loc.LocationID, away, getToken()); err != nil {
			log.Printf("failed to set away state on location %s: %v", loc.LocationID, err)
		}
		// Location-wide change, no specific device to /Refresh.
		pubSync <- ""
	})
}

// publishLocationState publishes the location-scoped state topics.
// awayState mirrors the value from any device's location.awayState
// (they're all the same within a location).
func publishLocationState(client mqtt.Client, loc Location, awayState int, online bool) {
	if !loc.SupportsAway {
		return
	}
	prefix := locationTopicPrefix(loc.LocationID)
	pub := func(topic, value string) {
		t := client.Publish(prefix+"/"+topic, 0, true, value)
		t.Wait()
	}
	if online {
		pub("availability", "online")
	} else {
		pub("availability", "offline")
	}
	pub("away/state", boolToOnOff(awayState == 1))
}

func main() {
	username := os.Getenv("WAHA_USER")
	pass := os.Getenv("WAHA_PASS")
	if username == "" || pass == "" {
		log.Fatal("WAHA_USER and WAHA_PASS are required")
	}

	tokensPath := envOrDefault("WAHA_TOKENS_PATH", "tokens.json")
	mqttBroker := envOrDefault("WAHA_MQTT_BROKER", "tcp://localhost:1883")
	mqttUser := os.Getenv("WAHA_MQTT_USER")
	mqttPass := os.Getenv("WAHA_MQTT_PASS")

	// Poll cadence. The official mobile app polls at a nominal ~40 s
	// interval when foregrounded (measured median 39.9 s across 10 clean
	// inter-poll gaps); match that as the default. Floor at 30 s — the
	// app doesn't go faster and we don't want to draw unwanted attention
	// from the backend. See docs/WATTS_API.md §9.
	pollInterval := 40 * time.Second
	if v := os.Getenv("WAHA_POLL_INTERVAL"); v != "" {
		parsed, err := time.ParseDuration(v)
		if err != nil {
			log.Fatalf("invalid WAHA_POLL_INTERVAL %q: %v", v, err)
		}
		if parsed < 30*time.Second {
			log.Printf("WAHA_POLL_INTERVAL %v is below 30 s floor; using 30 s", parsed)
			parsed = 30 * time.Second
		}
		pollInterval = parsed
	}

	// Authenticate with Watts API
	tokens := authenticate(username, pass, tokensPath)

	userDetails, err := GetUserDetails(tokens.AccessToken)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("hello %v", userDetails.Body.FirstName)

	locations, err := GetLocations(tokens.AccessToken)
	if err != nil {
		log.Fatal(err)
	}

	var defaultLocation Location
	for _, location := range locations.Body {
		if location.IsDefault && location.DevicesCount > 0 {
			defaultLocation = location
		} else if defaultLocation.LocationID == "" && location.DevicesCount > 0 {
			defaultLocation = location
		}
	}
	if defaultLocation.LocationID == "" {
		log.Fatal("no default location found!")
	}
	log.Printf("using location: %s", defaultLocation.Name)

	// Connect to MQTT
	opts := mqtt.NewClientOptions().
		AddBroker(mqttBroker).
		SetClientID(fmt.Sprintf("watts-bridge-%s", defaultLocation.LocationID)).
		SetAutoReconnect(true).
		SetConnectRetry(true).
		SetConnectRetryInterval(10 * time.Second).
		SetOnConnectHandler(func(_ mqtt.Client) {
			log.Println("connected to MQTT broker")
		}).
		SetConnectionLostHandler(func(_ mqtt.Client, err error) {
			log.Printf("MQTT connection lost: %v", err)
		})

	if mqttUser != "" {
		opts.SetUsername(mqttUser)
		opts.SetPassword(mqttPass)
	}

	mqttClient := mqtt.NewClient(opts)
	if token := mqttClient.Connect(); token.Wait() && token.Error() != nil {
		log.Fatalf("failed to connect to MQTT broker: %v", token.Error())
	}

	// Initial device fetch + discovery
	devices, err := GetDevices(defaultLocation.LocationID, tokens.AccessToken)
	if err != nil {
		log.Fatalf("failed to get devices: %v", err)
	}

	var tokensMu sync.Mutex

	deviceStates := &deviceState{
		devices:  map[string]MyDevice{},
		expected: map[string]expectedWrite{},
	}
	deviceStates.Update(devices.Body)

	pubSync := make(chan string, 4)

	// Track which devices we've already published discovery for. Offline
	// devices at startup are skipped (their data block is empty and HA's
	// validator rejects empty temperature_unit); we retry in doSync when
	// they come online. Discovery is idempotent on MQTT (retained), but
	// we avoid the extra work.
	publishedDiscovery := map[string]bool{}

	for _, device := range devices.Body {
		subscribeCommands(mqttClient, device, deviceStates, &tokens, username, pass, tokensPath, &tokensMu, pubSync)
		if device.IsConnected && device.Data.TempUnits.Val != "" {
			publishDiscovery(mqttClient, device)
			publishedDiscovery[device.DeviceID] = true
		} else {
			log.Printf("deferring discovery for %s (%s): device offline", device.Name, device.DeviceID)
		}
		publishState(mqttClient, device)
	}

	// Location-scoped entities (away switch).
	publishLocationDiscovery(mqttClient, defaultLocation)
	subscribeLocationCommands(mqttClient, defaultLocation, &tokens, username, pass, tokensPath, &tokensMu, pubSync)
	publishLocationState(mqttClient, defaultLocation, defaultLocation.AwayState, true)

	log.Printf("publishing state for %d device(s) every %v", len(devices.Body), pollInterval)

	// Poll loop
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	doSync := func(refreshDeviceID string) {
		// Re-authenticate if token is about to expire
		tokensMu.Lock()
		if tokens.ExpiresOn < int(time.Now().Add(2*time.Minute).Unix()) {
			log.Println("token expiring soon, re-authenticating")
			tokens = authenticate(username, pass, tokensPath)
		}

		// If a device just received a write, ask the server to pull a fresh
		// status from the thermostat before we re-fetch. Integration testing
		// showed /Device/{id}/Refresh updates data.DateTime within ~3 s,
		// but the actual setpoint values often take longer to propagate
		// (5+ s in practice). A short delay causes the post-write poll to
		// return stale values, which then overwrite HA's optimistic UI
		// update — the user sees "snap-back" 1 s after a setpoint change.
		// 5 s is empirically enough for most writes to land.
		if refreshDeviceID != "" {
			if _, err := API[any]("GET",
				fmt.Sprintf("/Device/%v/Refresh", url.PathEscape(refreshDeviceID)),
				nil, http.StatusOK, false, tokens.AccessToken); err != nil {
				log.Printf("post-write /Refresh on %s: %v", refreshDeviceID, err)
			}
			tokensMu.Unlock()
			time.Sleep(5 * time.Second)
			tokensMu.Lock()
		}

		devices, err := GetDevices(defaultLocation.LocationID, tokens.AccessToken)
		tokensMu.Unlock()
		if err != nil {
			log.Printf("failed to get devices: %v", err)
			return
		}

		// Overlay any pending user writes onto the polled data. The
		// cloud's read API lags writes by a variable amount (we've seen
		// 5–60 s); without this merge the post-write poll would publish
		// pre-write values to MQTT and HA's optimistic UI would snap
		// back. deviceStates.MergeExpected clears each field's pending
		// entry the moment the poll confirms it — so as soon as the
		// cloud catches up, we stop overriding.
		merged := make([]MyDevice, 0, len(devices.Body))
		for _, d := range devices.Body {
			merged = append(merged, deviceStates.MergeExpected(d))
		}
		deviceStates.Update(merged)

		// Location-scoped state — every connected device has the same
		// location.awayState. Pick any connected one; if none is connected,
		// preserve the last known state (MQTT retained) and mark offline.
		locationOnline := false
		locationAway := defaultLocation.AwayState
		for _, d := range merged {
			if d.IsConnected {
				locationOnline = true
				locationAway = d.Location.AwayState
				break
			}
		}
		publishLocationState(mqttClient, defaultLocation, locationAway, locationOnline)

		for _, device := range merged {
			// Publish discovery for any device we couldn't announce at
			// startup (it was offline) now that it has valid data.
			if !publishedDiscovery[device.DeviceID] && device.IsConnected && device.Data.TempUnits.Val != "" {
				log.Printf("publishing discovery for %s (%s) after reconnect", device.Name, device.DeviceID)
				publishDiscovery(mqttClient, device)
				publishedDiscovery[device.DeviceID] = true
			}
			publishState(mqttClient, device)
		}
	}

	for {
		select {
		case refreshID := <-pubSync:
			doSync(refreshID)

		case <-ticker.C:
			doSync("")

		case sig := <-sigCh:
			log.Printf("received %v, shutting down", sig)

			// Mark all devices as unavailable
			for _, device := range devices.Body {
				prefix := mqttTopicPrefix(device.DeviceID)
				t := mqttClient.Publish(prefix+"/availability", 0, true, "offline")
				t.Wait()
			}

			mqttClient.Disconnect(1000)
			return
		}
	}
}
