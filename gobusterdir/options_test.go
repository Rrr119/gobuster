package gobusterdir

import "testing"

func TestNewOptions(t *testing.T) {
	t.Parallel()

	o := NewOptions()
	if o.StatusCodesParsed.Set == nil {
		t.Fatal("StatusCodesParsed not initialized")
	}

	if o.ExtensionsParsed.Set == nil {
		t.Fatal("ExtensionsParsed not initialized")
	}

	if !o.Soft404Detection {
		t.Fatal("Soft404Detection should be enabled by default")
	}

	if o.Soft404Threshold != DefaultSoft404Threshold {
		t.Fatalf("Soft404Threshold = %f, want %f", o.Soft404Threshold, DefaultSoft404Threshold)
	}

	if !o.Deduplicate {
		t.Fatal("Deduplicate should be enabled by default")
	}

	if o.ClusterThreshold != DefaultClusterThreshold {
		t.Fatalf("ClusterThreshold = %f, want %f", o.ClusterThreshold, DefaultClusterThreshold)
	}
}
