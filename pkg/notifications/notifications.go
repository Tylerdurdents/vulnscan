package notifications

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/eonedge/vulnscan/pkg/scanner"
	"github.com/eonedge/vulnscan/pkg/utils"
)

// NotificationType represents the type of notification
type NotificationType string

const (
	NotificationEmail   NotificationType = "email"
	NotificationSlack   NotificationType = "slack"
	NotificationWebhook NotificationType = "webhook"
)

// NotificationConfig holds notification configuration
type NotificationConfig struct {
	Type     NotificationType
	Settings map[string]string
}

// Notification represents a notification to be sent
type Notification struct {
	Subject string
	Body    string
}

// Notifier handles sending notifications
type Notifier struct {
	config NotificationConfig
	client *http.Client
	logger *utils.Logger
}

// NewNotifier creates a new notifier
func NewNotifier(config NotificationConfig) *Notifier {
	return &Notifier{
		config: config,
		client: &http.Client{Timeout: 30 * time.Second},
		logger: utils.NewLogger(utils.INFO, "NOTIFY"),
	}
}

// Send sends a notification
func (n *Notifier) Send(notification Notification) error {
	switch n.config.Type {
	case NotificationEmail:
		return n.sendEmail(notification)
	case NotificationSlack:
		return n.sendSlack(notification)
	case NotificationWebhook:
		return n.sendWebhook(notification)
	default:
		return fmt.Errorf("unsupported notification type: %s", n.config.Type)
	}
}

// SendScanResult sends a scan result notification
func (n *Notifier) SendScanResult(result *scanner.ScanResult) error {
	subject := fmt.Sprintf("VulnScan Report: %s", result.Target)
	body := n.formatScanResult(result)

	return n.Send(Notification{
		Subject: subject,
		Body:    body,
	})
}

// formatScanResult formats a scan result for notification
func (n *Notifier) formatScanResult(result *scanner.ScanResult) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Target: %s\n", result.Target))
	sb.WriteString(fmt.Sprintf("Endpoints scanned: %d\n", result.Endpoints))
	sb.WriteString(fmt.Sprintf("Vulnerabilities found: %d\n", len(result.Vulnerabilities)))
	sb.WriteString(fmt.Sprintf("Duration: %v\n", result.Duration))
	sb.WriteString("\n")

	if len(result.Vulnerabilities) > 0 {
		sb.WriteString("Vulnerabilities by severity:\n")
		severityCount := make(map[string]int)
		for _, vuln := range result.Vulnerabilities {
			severityCount[string(vuln.Severity)]++
		}
		for severity, count := range severityCount {
			sb.WriteString(fmt.Sprintf("  %s: %d\n", severity, count))
		}
	}

	return sb.String()
}

// sendEmail sends an email notification
func (n *Notifier) sendEmail(notification Notification) error {
	smtpHost := n.config.Settings["smtp_host"]
	smtpPort := n.config.Settings["smtp_port"]
	username := n.config.Settings["username"]
	password := n.config.Settings["password"]
	from := n.config.Settings["from"]
	to := n.config.Settings["to"]

	if smtpHost == "" || smtpPort == "" || from == "" || to == "" {
		return fmt.Errorf("missing email configuration")
	}

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		from, to, notification.Subject, notification.Body)

	auth := smtp.PlainAuth("", username, password, smtpHost)
	addr := fmt.Sprintf("%s:%s", smtpHost, smtpPort)

	err := smtp.SendMail(addr, auth, from, []string{to}, []byte(msg))
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	n.logger.Info("Email notification sent to %s", to)
	return nil
}

// sendSlack sends a Slack notification
func (n *Notifier) sendSlack(notification Notification) error {
	webhookURL := n.config.Settings["webhook_url"]
	if webhookURL == "" {
		return fmt.Errorf("missing Slack webhook URL")
	}

	payload := map[string]interface{}{
		"text": fmt.Sprintf("*%s*\n%s", notification.Subject, notification.Body),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal Slack payload: %w", err)
	}

	resp, err := n.client.Post(webhookURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to send Slack notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Slack returned status %d", resp.StatusCode)
	}

	n.logger.Info("Slack notification sent")
	return nil
}

// sendWebhook sends a webhook notification
func (n *Notifier) sendWebhook(notification Notification) error {
	webhookURL := n.config.Settings["webhook_url"]
	if webhookURL == "" {
		return fmt.Errorf("missing webhook URL")
	}

	payload := map[string]interface{}{
		"subject": notification.Subject,
		"body":    notification.Body,
		"timestamp": time.Now().Unix(),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	resp, err := n.client.Post(webhookURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to send webhook notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	n.logger.Info("Webhook notification sent to %s", webhookURL)
	return nil
}
