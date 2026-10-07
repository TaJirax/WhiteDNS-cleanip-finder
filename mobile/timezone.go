package mobile

import "time"

// SetTimeZone makes engine timestamps (result file names, logs) use the
// device's zone. Go on Android has no TZ and starts in UTC; the app passes
// java.util.TimeZone.getDefault().id (for example "Asia/Tehran") at launch.
func SetTimeZone(name string) error {
	loc, err := time.LoadLocation(name)
	if err != nil {
		return err
	}
	time.Local = loc
	return nil
}
