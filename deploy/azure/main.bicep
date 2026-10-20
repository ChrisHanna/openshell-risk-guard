// SPDX-License-Identifier: Apache-2.0
// Retired intentionally: this file creates no resources.
// The former ACI group ran a dashboard plus a curl polling loop. It did not
// launch an OpenShell gateway, isolation runtime, supervisor or extension RPCs.
// A public dashboard and emptyDir SQLite are not a secure production deployment.
// Local integration prerequisites and verified registration are in ../local/.
output status string = 'Disabled: no OpenShell deployment; no resources created.'
