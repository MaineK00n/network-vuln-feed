package fortinet

import (
	"encoding/xml"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/exp/maps"
)

func Discover(rssURL string, rootpath string) error {
	resp, err := http.Get(rssURL)
	if err != nil {
		return errors.Wrapf(err, "get %s", rssURL)
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New("status is not ok")
	}
	defer resp.Body.Close()

	var rss rss
	if err := xml.NewDecoder(resp.Body).Decode(&rss); err != nil {
		return errors.Wrap(err, "decode xml")
	}

	advs := map[string]struct{}{}
	for _, i := range rss.Channel.Item {
		u, err := url.Parse(i.Link)
		if err != nil {
			return errors.Wrapf(err, "parse %s", i.Link)
		}
		advs[path.Base(u.Path)] = struct{}{}
	}

	if err := filepath.WalkDir(rootpath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if filepath.Ext(path) != ".json" {
			return nil
		}

		delete(advs, strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)))

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", rootpath)
	}

	if len(advs) > 0 {
		return errors.Errorf("discover new advisory: %q", maps.Keys(advs))
	}

	return nil
}
