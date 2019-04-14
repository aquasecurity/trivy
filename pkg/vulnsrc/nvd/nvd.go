package nvd

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/knqyf263/trivy/pkg/db"
	"github.com/knqyf263/trivy/pkg/log"
	"golang.org/x/xerrors"
	pb "gopkg.in/cheggaaa/pb.v1"
)

const (
	baseURL = "https://nvd.nist.gov/feeds/json/cve/1.0"
)

func Update() error {
	now := time.Now()

	var old bool
	var feeds []string
	for _, feed := range []string{"modified", "recent"} {
		lastModifiedDate, err := fetchLastModifiedDate(feed)
		if err != nil {
			return err
		}
		lastUpdatedDate, err := getLastUpdatedDate()
		if err != nil {
			return err
		}

		if lastUpdatedDate.After(lastModifiedDate) {
			continue
		}
		feeds = append(feeds, feed)

		duration := lastModifiedDate.Sub(lastUpdatedDate)
		if duration > 24*time.Hour*7 {
			old = true
		}
	}

	if old {
		// Fetch all years
		for year := 2002; year <= now.Year(); year++ {
			feeds = append(feeds, fmt.Sprint(year))
		}
	}

	feedCount := len(feeds)
	if feedCount == 0 {
		return nil
	}

	log.Logger.Info("Fetching NVD data...")
	bar := pb.StartNew(feedCount)

	results := make(chan *NVD)
	errCh := make(chan error)
	limit := make(chan struct{}, 5)
	for _, feed := range feeds {
		go func(feed string) {
			limit <- struct{}{}
			nvd, err := fetchJson(feed)
			if err != nil {
				errCh <- err
				return
			}
			results <- nvd
			<-limit
		}(feed)
	}

	for i := 0; i < feedCount; i++ {
		select {
		case nvd := <-results:
			if err := save(nvd); err != nil {
				return err
			}
		case err := <-errCh:
			return err
		}
		bar.Increment()
	}
	setLastUpdatedDate(now)

	return nil

}

func getLastUpdatedDate() (time.Time, error) {
	lastUpdated := LastUpdated{}
	value, err := db.Get("NVD", "Last Update")
	if err != nil {
		return time.Time{}, err
	}
	if len(value) == 0 {
		return time.Unix(0, 0), nil
	}
	if err = json.Unmarshal(value, &lastUpdated); err != nil {
		return time.Time{}, err
	}
	return lastUpdated.Date, nil
}

func setLastUpdatedDate(lastUpdatedDate time.Time) error {
	d := LastUpdated{Date: lastUpdatedDate}
	return db.Update("NVD", "Last Update", d)
}

func save(nvd *NVD) error {
	data := map[string]interface{}{}
	for _, item := range nvd.CVEItems {
		cveID := item.Cve.Meta.ID
		data[cveID] = item
	}
	return db.BatchUpdate("NVD", data)
}

func Get(cveID string) (*Item, error) {
	value, err := db.Get("NVD", cveID)
	if err != nil {
		return nil, err
	}
	if len(value) == 0 {
		return nil, nil
	}

	var item *Item
	if err = json.Unmarshal(value, &item); err != nil {
		return nil, err
	}
	return item, nil
}

func fetchLastModifiedDate(feed string) (time.Time, error) {
	log.Logger.Infof("Fetching NVD metadata(%s)...", feed)

	url := fmt.Sprintf("%s/nvdcve-1.0-%s.meta", baseURL, feed)
	res, err := http.Get(url)
	if err != nil {
		return time.Time{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return time.Time{}, xerrors.New("error")
	}

	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		line := scanner.Text()
		s := strings.SplitN(line, ":", 2)
		if len(s) != 2 {
			continue
		}
		if s[0] == "lastModifiedDate" {
			t, err := time.Parse(time.RFC3339, s[1])
			if err != nil {
				return time.Time{}, err
			}
			return t, nil
		}
	}
	return time.Unix(0, 0), nil

}

func fetchJson(feed string) (*NVD, error) {
	url := fmt.Sprintf("%s/nvdcve-1.0-%s.json.gz", baseURL, feed)

	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, xerrors.New("error")
	}

	zr, err := gzip.NewReader(res.Body)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	nvd := &NVD{}
	err = json.NewDecoder(zr).Decode(nvd)
	if err != nil {
		return nil, err
	}
	return nvd, nil
}
