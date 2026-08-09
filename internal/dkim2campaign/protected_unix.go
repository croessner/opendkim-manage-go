//go:build darwin || linux

package dkim2campaign

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type protectedDirectory struct {
	fd  int
	uid uint32
}

func openProtectedDirectory(path string) (*protectedDirectory, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errCampaign
	}
	var status unix.Stat_t
	if err = unix.Fstat(fd, &status); err != nil || status.Mode&unix.S_IFMT != unix.S_IFDIR ||
		status.Uid != uint32(os.Geteuid()) || status.Mode&0o777 != 0o700 {
		_ = unix.Close(fd)
		return nil, errCampaign
	}
	return &protectedDirectory{fd: fd, uid: status.Uid}, nil
}

func (d *protectedDirectory) close() error {
	if d == nil || d.fd < 0 {
		return nil
	}
	err := unix.Close(d.fd)
	d.fd = -1
	if err != nil {
		return errCampaign
	}
	return nil
}

func (d *protectedDirectory) openRegular(name string, maximum int64) (*os.File, int64, error) {
	if d == nil || d.fd < 0 || !directName(name) || maximum < 1 {
		return nil, 0, errCampaign
	}
	fd, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, err
	}
	var status unix.Stat_t
	if err = unix.Fstat(fd, &status); err != nil || status.Mode&unix.S_IFMT != unix.S_IFREG ||
		status.Uid != d.uid || status.Mode&0o077 != 0 || status.Size < 1 || status.Size > maximum {
		_ = unix.Close(fd)
		return nil, 0, errCampaign
	}
	return os.NewFile(uintptr(fd), name), status.Size, nil
}

func (d *protectedDirectory) readRegular(name string, maximum int64) ([]byte, bool, error) {
	file, size, err := d.openRegular(name, maximum)
	if errors.Is(err, unix.ENOENT) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, errCampaign
	}
	document, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(document)) != size {
		clear(document)
		return nil, false, errCampaign
	}
	return document, true, nil
}

func (d *protectedDirectory) regularPresent(name string, maximum int64) (bool, error) {
	file, _, err := d.openRegular(name, maximum)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, errCampaign
	}
	if err := file.Close(); err != nil {
		return false, errCampaign
	}
	return true, nil
}

func (d *protectedDirectory) removeRegularIfPresent(name string, maximum int64) error {
	file, _, err := d.openRegular(name, maximum)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return errCampaign
	}
	if err := file.Close(); err != nil {
		return errCampaign
	}
	if err := unix.Unlinkat(d.fd, name, 0); err != nil {
		return errCampaign
	}
	return nil
}

func (d *protectedDirectory) replace(name string, document []byte) error {
	if d == nil || d.fd < 0 || !directName(name) || len(document) == 0 {
		return errCampaign
	}
	temporary := name + ".new"
	if err := d.removeOwnedRegularIfPresent(temporary); err != nil {
		return errCampaign
	}
	fd, err := unix.Openat(d.fd, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return errCampaign
	}
	file := os.NewFile(uintptr(fd), temporary)
	if _, err = file.Write(document); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = unix.Renameat(d.fd, temporary, d.fd, name)
	}
	if err != nil {
		_ = unix.Unlinkat(d.fd, temporary, 0)
		return errCampaign
	}
	if err := unix.Fsync(d.fd); err != nil {
		return errCampaign
	}
	return nil
}

func (d *protectedDirectory) removeOwnedRegularIfPresent(name string) error {
	if d == nil || d.fd < 0 || !directName(name) {
		return errCampaign
	}
	fd, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return errCampaign
	}
	var status unix.Stat_t
	statErr := unix.Fstat(fd, &status)
	closeErr := unix.Close(fd)
	if statErr != nil || closeErr != nil || status.Mode&unix.S_IFMT != unix.S_IFREG || status.Uid != d.uid || status.Mode&0o077 != 0 {
		return errCampaign
	}
	if err := unix.Unlinkat(d.fd, name, 0); err != nil {
		return errCampaign
	}
	return nil
}

func directName(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name
}
