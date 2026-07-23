package proxy

import "time"

// nowFn is overridable in tests.
var nowFn = func() time.Time { return time.Now().UTC() }
