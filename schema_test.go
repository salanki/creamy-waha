package main_test

import (
	"encoding/json"
	"os"
	"testing"

	main "go.home/watts-app-re"
)

// TestDeviceSchema563RadiantHumidifier validates that the MyDevice struct
// decodes a realistic Tekmar 563 payload (with radiant floor sensor and
// humidifier accessory, heat-pump emergency mode) without loss.
func TestDeviceSchema563RadiantHumidifier(t *testing.T) {
	raw, err := os.ReadFile("testdata/device_563_radiant_humidifier.json")
	if err != nil {
		t.Fatal(err)
	}

	var d main.MyDevice
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Top-level identity
	if d.ModelNumber != "563" {
		t.Errorf("ModelNumber: got %q, want %q", d.ModelNumber, "563")
	}
	if d.ModelID != 8 {
		t.Errorf("ModelID: got %d, want 8", d.ModelID)
	}
	if !d.IsConnected {
		t.Errorf("IsConnected: got false, want true")
	}

	// Runtime state
	if d.Data.State.Op != "Off" {
		t.Errorf("State.Op: got %q, want %q", d.Data.State.Op, "Off")
	}
	if d.Data.State.Sub != "None" {
		t.Errorf("State.Sub: got %q, want %q (the string 'None', not JSON null)", d.Data.State.Sub, "None")
	}
	if d.Data.Fan.Relay != 0 {
		t.Errorf("Fan.Relay: got %d, want 0", d.Data.Fan.Relay)
	}

	// Capabilities
	if d.Data.Hum.Active != 1 {
		t.Errorf("Hum.Active: got %d, want 1", d.Data.Hum.Active)
	}
	if d.Data.Dehum.Active != 0 {
		t.Errorf("Dehum.Active: got %d, want 0", d.Data.Dehum.Active)
	}
	wantModeEnum := []string{"Off", "Heat", "Cool", "Auto", "Emer"}
	if len(d.Data.Mode.Enum) != len(wantModeEnum) {
		t.Errorf("Mode.Enum length: got %d, want %d", len(d.Data.Mode.Enum), len(wantModeEnum))
	}
	for i, want := range wantModeEnum {
		if i < len(d.Data.Mode.Enum) && d.Data.Mode.Enum[i] != want {
			t.Errorf("Mode.Enum[%d]: got %q, want %q", i, d.Data.Mode.Enum[i], want)
		}
	}

	// Sensors
	if d.Data.Sensors.Floor.Status != "Okay" {
		t.Errorf("Sensors.Floor.Status: got %q, want %q", d.Data.Sensors.Floor.Status, "Okay")
	}
	if d.Data.Sensors.Room.Value != 68 {
		t.Errorf("Sensors.Room.Value: got %v, want 68", d.Data.Sensors.Room.Value)
	}

	// Schedule.Floor — the 5xx-specific user-writable floor minimums (new field).
	if d.Data.Schedule.Floor.W != 67 {
		t.Errorf("Schedule.Floor.W: got %v, want 67", d.Data.Schedule.Floor.W)
	}
	if d.Data.Schedule.Floor.A != 66 {
		t.Errorf("Schedule.Floor.A: got %v, want 66", d.Data.Schedule.Floor.A)
	}
	// Read-only hardware limits — distinct from Schedule.Floor.{W,A}.
	if d.Data.Schedule.FloorMin != 40 {
		t.Errorf("Schedule.FloorMin: got %v, want 40", d.Data.Schedule.FloorMin)
	}
	if d.Data.Schedule.FloorMax != 80 {
		t.Errorf("Schedule.FloorMax: got %v, want 80", d.Data.Schedule.FloorMax)
	}
	if d.Data.Schedule.FloorActive != 1 {
		t.Errorf("Schedule.FloorActive: got %d, want 1", d.Data.Schedule.FloorActive)
	}

	// Interlocks (top-level under data).
	if d.Data.TempInterlock != 2.0 {
		t.Errorf("TempInterlock: got %v, want 2.0", d.Data.TempInterlock)
	}
	if d.Data.HumInterlock != 1 {
		t.Errorf("HumInterlock: got %d, want 1", d.Data.HumInterlock)
	}

	// Empty schedule groups should decode as zero-value ScheduleGroup without error.
	if d.Data.Schedule.Grp1.Days != "MTWRF" {
		t.Errorf("Schedule.Grp1.Days: got %q, want %q", d.Data.Schedule.Grp1.Days, "MTWRF")
	}
	if d.Data.Schedule.Grp4.Days != "" {
		t.Errorf("Schedule.Grp4.Days: got %q, want empty (group is {})", d.Data.Schedule.Grp4.Days)
	}

	// Energy
	if len(d.Data.Energy.Heat.Daily) != 7 {
		t.Errorf("Energy.Heat.Daily: got %d entries, want 7", len(d.Data.Energy.Heat.Daily))
	}
	if len(d.Data.Energy.Heat.Monthly) != 12 {
		t.Errorf("Energy.Heat.Monthly: got %d entries, want 12", len(d.Data.Energy.Heat.Monthly))
	}
}

// TestDeviceSchema563Disconnected ensures a device with isConnected:false
// and a missing/empty data block decodes without error — the bridge must
// handle this gracefully (publish availability=offline, retain last state).
func TestDeviceSchema563Disconnected(t *testing.T) {
	raw := []byte(`{
		"deviceId": "00000000-0000-0000-0000-000000000001",
		"name": "Offline Device",
		"modelNumber": "563",
		"isConnected": false,
		"data": {}
	}`)

	var d main.MyDevice
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("unmarshal disconnected device: %v", err)
	}

	if d.IsConnected {
		t.Errorf("IsConnected: got true, want false")
	}
	if d.Name != "Offline Device" {
		t.Errorf("Name: got %q, want %q", d.Name, "Offline Device")
	}
	if len(d.Data.Mode.Enum) != 0 {
		t.Errorf("Mode.Enum on disconnected device: got %v, want empty", d.Data.Mode.Enum)
	}
}
