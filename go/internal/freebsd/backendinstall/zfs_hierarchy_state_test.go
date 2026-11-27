// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"testing"
)

func setExpectedFIDatasetResponses(
	probe *fakeHostProbe,
	spec fiDatasetSpec,
) {
	target := spec.Target

	probe.responses["zfs get -H -o value,source org.ironsignal.fi:managed "+target] =
		fakeHostProbeResponse{
			output: "1\tlocal\n",
		}

	probe.responses["zfs get -H -o value,source org.ironsignal.fi:schema "+target] =
		fakeHostProbeResponse{
			output: "1\tlocal\n",
		}

	probe.responses["zfs get -H -o value,source org.ironsignal.fi:role "+target] =
		fakeHostProbeResponse{
			output: spec.Role + "\tlocal\n",
		}

	probe.responses["zfs get -H -o value,source mountpoint "+target] =
		fakeHostProbeResponse{
			output: spec.Mountpoint + "\tlocal\n",
		}

	probe.responses["zfs get -H -o value,source canmount "+target] =
		fakeHostProbeResponse{
			output: spec.Canmount + "\tlocal\n",
		}

	probe.responses["zfs get -H -o value,source atime "+target] =
		fakeHostProbeResponse{
			output: "off\tlocal\n",
		}

	probe.responses["zfs get -H -o value,source exec "+target] =
		fakeHostProbeResponse{
			output: "off\tlocal\n",
		}

	probe.responses["zfs get -H -o value,source setuid "+target] =
		fakeHostProbeResponse{
			output: "off\tlocal\n",
		}

	probe.responses["zfs get -H -o value,source devices "+target] =
		fakeHostProbeResponse{
			output: "off\tlocal\n",
		}

	probe.responses["zfs get -H -o value mounted "+target] =
		fakeHostProbeResponse{
			output: spec.Mounted + "\n",
		}
}

func TestInspectFIDatasetStates(t *testing.T) {
	config := loadTestConfig(t)
	spec := fiHierarchySpecs(config)[4]

	tests := []struct {
		name      string
		configure func(*fakeHostProbe)
		want      fiDatasetState
	}{
		{
			name: "absent",
			configure: func(probe *fakeHostProbe) {
				probe.responses["zfs list -H -t filesystem -o name"] =
					fakeHostProbeResponse{
						output: "zroot\nzroot/fi\n",
					}
			},
			want: fiDatasetAbsent,
		},
		{
			name: "inspection failure",
			configure: func(probe *fakeHostProbe) {
				probe.responses["zfs list -H -t filesystem -o name"] =
					fakeHostProbeResponse{
						err: fmt.Errorf("list failed"),
					}
			},
			want: fiDatasetUnknown,
		},
		{
			name: "foreign dataset",
			configure: func(probe *fakeHostProbe) {
				probe.responses["zfs list -H -t filesystem -o name"] =
					fakeHostProbeResponse{
						output: "zroot\nzroot/fi\nzroot/fi/ready\n",
					}

				probe.responses["zfs get -H -o value,source org.ironsignal.fi:managed zroot/fi/ready"] =
					fakeHostProbeResponse{
						output: "-\t-\n",
					}
			},
			want: fiDatasetForeignCollision,
		},
		{
			name: "inherited ownership",
			configure: func(probe *fakeHostProbe) {
				probe.responses["zfs list -H -t filesystem -o name"] =
					fakeHostProbeResponse{
						output: "zroot\nzroot/fi\nzroot/fi/ready\n",
					}

				probe.responses["zfs get -H -o value,source org.ironsignal.fi:managed zroot/fi/ready"] =
					fakeHostProbeResponse{
						output: "1\tinherited\n",
					}
			},
			want: fiDatasetForeignCollision,
		},
		{
			name: "owned role drift",
			configure: func(probe *fakeHostProbe) {
				probe.responses["zfs list -H -t filesystem -o name"] =
					fakeHostProbeResponse{
						output: "zroot\nzroot/fi\nzroot/fi/ready\n",
					}

				setExpectedFIDatasetResponses(
					probe,
					spec,
				)

				probe.responses["zfs get -H -o value,source org.ironsignal.fi:role zroot/fi/ready"] =
					fakeHostProbeResponse{
						output: "wrong-role\tlocal\n",
					}
			},
			want: fiDatasetOwnedDrift,
		},
		{
			name: "inherited controlled property",
			configure: func(probe *fakeHostProbe) {
				probe.responses["zfs list -H -t filesystem -o name"] =
					fakeHostProbeResponse{
						output: "zroot\nzroot/fi\nzroot/fi/ready\n",
					}

				setExpectedFIDatasetResponses(
					probe,
					spec,
				)

				probe.responses["zfs get -H -o value,source atime zroot/fi/ready"] =
					fakeHostProbeResponse{
						output: "off\tinherited\n",
					}
			},
			want: fiDatasetOwnedDrift,
		},
		{
			name: "runtime mounted drift",
			configure: func(probe *fakeHostProbe) {
				probe.responses["zfs list -H -t filesystem -o name"] =
					fakeHostProbeResponse{
						output: "zroot\nzroot/fi\nzroot/fi/ready\n",
					}

				setExpectedFIDatasetResponses(
					probe,
					spec,
				)

				probe.responses["zfs get -H -o value mounted zroot/fi/ready"] =
					fakeHostProbeResponse{
						output: "no\n",
					}
			},
			want: fiDatasetOwnedDrift,
		},
		{
			name: "owned match",
			configure: func(probe *fakeHostProbe) {
				probe.responses["zfs list -H -t filesystem -o name"] =
					fakeHostProbeResponse{
						output: "zroot\nzroot/fi\nzroot/fi/ready\n",
					}

				setExpectedFIDatasetResponses(
					probe,
					spec,
				)
			},
			want: fiDatasetOwnedMatch,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			probe := validFakeHostProbe()

			test.configure(&probe)

			got := inspectFIDatasetState(
				&probe,
				spec,
			)

			if got != test.want {
				t.Fatalf(
					"inspectFIDatasetState() = %s, want %s",
					got,
					test.want,
				)
			}
		})
	}
}
