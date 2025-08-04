package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"

	errors "github.com/oarkflow/stack"
	"github.com/oarkflow/stack/logs"
)

func main() {
	fmt.Println("=== Error Framework Demo ===\n")
	fmt.Println(errors.ParseID("689072FD-api-n/a-2-500"))

	// Environment Setup
	fmt.Println("1. Environment Setup:")
	env := os.Getenv("APP_ENV")
	if env == "" {
		env = "development"
	}
	fmt.Printf("Current Environment: %s\n\n", env)

	// Configure framework based on environment
	config := errors.DefaultConfig()
	if env == "production" {
		config.DebugMode = false
	} else {
		config.DebugMode = true
	}
	errors.SetConfig(config)

	// HTTP Integration
	fmt.Println("2. HTTP Integration:")
	http.HandleFunc("/error-demo", func(w http.ResponseWriter, r *http.Request) {
		err := errors.NewAPIError(500, "HTTP_001", "Internal server error", map[string]string{
			"endpoint": r.URL.Path,
			"method":   r.Method,
		})
		errors.PrintErrorDetails(err.ID)
		http.Error(w, err.Message, err.Status)
	})

	http.HandleFunc("/error-page", func(w http.ResponseWriter, r *http.Request) {
		errors.RenderErrorPage(w, 404, "Page Not Found", "The requested page does not exist.", "Check the URL and try again.", "Technical details here", "/retry")
	})

	fmt.Println("Starting HTTP server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))

	// Logger Configuration
	fmt.Println("3. Logger Configuration:")
	slogLogger := logs.NewSlogLogger(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))
	errors.SetGlobalLogger(slogLogger)

	err := errors.NewCriticalError(errors.DomainSystem, "SYS_001", "System failure", map[string]string{
		"component": "database",
		"action":    "restart_required",
	})
	fmt.Printf("Critical Error: %s\n\n", err)

	// Database Integration
	fmt.Println("4. Database Integration:")
	// Example: Integrate with PostgreSQL for error storage
	// db, err := sql.Open("postgres", "user=postgres dbname=errors sslmode=disable")
	// if err != nil {
	//     log.Fatalf("Failed to connect to database: %v", err)
	// }
	// errors.SetDatabase(db)

	// HTTP Middleware
	fmt.Println("5. HTTP Middleware:")
	// Example: Middleware for automatic error handling
	// http.Handle("/", errors.ErrorMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	//     fmt.Fprintln(w, "Hello, World!")
	// })))

	// Metrics Integration
	fmt.Println("6. Metrics Integration:")
	// Example: Integrate with Prometheus
	// errors.RegisterMetricsCallback(func(err errors.Error) {
	//     prometheus.CounterVec.WithLabelValues(err.Domain, err.Severity).Inc()
	// })

	// Error Categorization
	fmt.Println("7. Error Categorization:")
	// Example: Categorize errors
	// validationErr := errors.NewValidationError("VALIDATION_001", "Invalid input", nil)
	// fmt.Printf("Validation Error: %s\n", validationErr)

	// Error Notification
	fmt.Println("8. Error Notification:")
	// Example: Send notifications for critical errors
	// errors.RegisterNotificationCallback(func(err errors.Error) {
	//     if err.Severity == errors.SeverityCritical {
	//         sendSlackNotification(err)
	//     }
	// })

	// Error Dashboard
	fmt.Println("9. Error Dashboard:")
	// Example: Build a web-based dashboard for error visualization
	// errors.StartDashboardServer(":9090")

	fmt.Println("\n=== Demo Complete ===")
}
