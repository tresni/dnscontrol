package notifications

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

func init() {
	inits = append(inits, func(cfg map[string]string) Notifier {
		if url, ok := cfg["slack_url"]; ok {
			return &slackNotifier{url: url}
		}
		return nil
	})
}

type slackNotifier struct {
	url     string
	sentAny bool
}

func (s *slackNotifier) Notify(domain, provider, msg string, err error, preview bool) {
	if !s.sentAny {
		s.maybeLinkToTeamCity()
	}
	s.sentAny = true
	var payload string
	if preview {
		payload = fmt.Sprintf(`*Preview: %s[%s] -* %s`, domain, provider, msg)
	} else if err != nil {
		payload = fmt.Sprintf(`*ERROR running correction on %s[%s] -* (%s) Error: %s`, domain, provider, msg, err)
	} else {
		payload = fmt.Sprintf(`Successfully ran correction for *%s[%s]* - %s`, domain, provider, msg)
	}
	s.sendMessage(payload)
}

func (s *slackNotifier) sendMessage(payload string) {
	slackObj := struct {
		Text    string `json:"text"`
		IconURL string `json:"icon_url"`
	}{
		Text:    payload,
		IconURL: "https://i.stack.imgur.com/UOTu2.png?g&s=256",
	}
	if dat, err := json.Marshal(slackObj); err == nil {
		http.Post(s.url, "application/json", bytes.NewReader(dat))
	}
}

func (s *slackNotifier) maybeLinkToTeamCity() {

}

func (b slackNotifier) Done() {}
