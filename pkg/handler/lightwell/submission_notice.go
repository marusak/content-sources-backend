package lightwell

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/content-services/content-sources-backend/pkg/clients/bop_client"
	"github.com/content-services/content-sources-backend/pkg/config"
	"github.com/rs/zerolog/log"
)

const submissionReviewLine = "Log in into console.redhat.com/lightwell/submission to review this submission."

// notifySubmitted emails the TAMs for a submitted clearinghouse submission.
// Tests replace it to keep handler tests off the Back Office Proxy.
var notifySubmitted = notifySubmittedClearinghouse

// notifySubmittedClearinghouse emails the TAMs for the customer's CID. When
// the CID has no TAM, it emails LIGHTWELL_DEFAULT_TAM_EMAILS instead. A
// failure is logged by the caller and does not fail the submission.
func notifySubmittedClearinghouse(ctx context.Context, orgID string) error {
	lightwell := config.Get().Clients.Lightwell
	cid := lightwell.ClearinghouseMapping.CIDForOrg(orgID)
	if cid == "" {
		return fmt.Errorf("org %s has no clearinghouse CID", orgID)
	}
	defaults, err := config.ParseEmailList(lightwell.DefaultTamEmails)
	if err != nil {
		return fmt.Errorf("parse LIGHTWELL_DEFAULT_TAM_EMAILS: %w", err)
	}

	tams := lightwell.ClearinghouseMapping.TAMsForOrg(orgID)
	var emailsByUsername map[string]string
	if len(tams) > 0 {
		client, err := bop_client.New(config.Get().Clients.BOP)
		if err != nil {
			return err
		}
		lookupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		emailsByUsername, err = client.EmailsByUsername(lookupCtx, tams)
		if err != nil {
			return err
		}
	}

	notice, missing := submissionNotice(cid, tams, emailsByUsername, defaults)
	if len(missing) > 0 {
		log.Error().Str("org_id", orgID).Str("cid", cid).Strs("usernames", missing).Msg("clearinghouse TAM has no email address")
	}
	if len(notice.to) == 0 {
		if len(tams) == 0 {
			log.Warn().Str("org_id", orgID).Str("cid", cid).Msg("clearinghouse submission has no TAM and LIGHTWELL_DEFAULT_TAM_EMAILS is empty")
			return nil
		}
		return fmt.Errorf("no email addresses for clearinghouse TAMs of %s", cid)
	}

	client, err := bop_client.New(config.Get().Clients.BOP)
	if err != nil {
		return err
	}
	sendCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return client.SendEmail(sendCtx, notice.to, notice.subject, notice.body)
}

type submissionEmail struct {
	to      []string
	subject string
	body    string
}

func submissionNotice(cid string, tams []string, emailsByUsername map[string]string, defaults []string) (submissionEmail, []string) {
	if len(tams) == 0 {
		return submissionEmail{
			to:      append([]string(nil), defaults...),
			subject: fmt.Sprintf("New submission created for %s that does not have TAM assigned", cid),
			body:    submissionReviewLine + "\n" + fmt.Sprintf("Set up TAM for %s", cid),
		}, nil
	}

	seen := make(map[string]struct{}, len(tams))
	var to []string
	var missing []string
	for _, username := range tams {
		email := ""
		if emailsByUsername != nil {
			email = emailsByUsername[strings.ToLower(username)]
		}
		if email == "" {
			missing = append(missing, username)
			continue
		}
		if _, ok := seen[email]; ok {
			continue
		}
		seen[email] = struct{}{}
		to = append(to, email)
	}
	slices.Sort(to)
	return submissionEmail{
		to:      to,
		subject: fmt.Sprintf("New submission for %s created.", cid),
		body:    submissionReviewLine,
	}, missing
}
