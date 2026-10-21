//go:build !windows

package logtail

func (t *Tailer) tailSource(src string) {
	t.tailFile(src)
}
