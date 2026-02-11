package main

import (
	"bufio"
	"math/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"upd/common/types"
	crand "crypto/rand"
	"encoding/hex"
	"github.com/go-redis/redis/v8"
	"context"
	"strconv"
)

const (
	MAX_UPLOAD_SIZE = 100 << 20
	UPLOAD_DIR      = "./uploads"
	ENV_FILE        = ".env"
	COUNTDOWN_DAYS  = 25
)

var (
	API_KEYS   = make(map[string]bool)
	PORT       string
	keysMutex  sync.RWMutex
)

// Struct untuk menyimpan key sementara dengan expiry time
type tempKey struct {
	Key    string
	Expiry time.Time
}

var (
	tempKeys     = make(map[string]tempKey)
	tempKeysLock sync.RWMutex
)

var (
	redisClient *redis.Client
	ctx         = context.Background()
)

func init() {
	loadEnvFile()
	loadEnvVars()
	
	PORT = os.Getenv("PORT")
	if PORT == "" {
		PORT = "7860"
	}
	
	// Seed untuk math/rand (digunakan di fungsi lain seperti generateFilename)
	rand.Seed(time.Now().UnixNano())
	
	fmt.Printf("🔑 Loaded %d API keys\n", len(API_KEYS))
	if len(API_KEYS) == 0 {
		fmt.Println("⚠️  Warning: No API keys loaded! Add API_KEY=yourkey to .env file")
	}

	initRedis()
	
	// Bersihkan key yang expired setiap 5 menit
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		
		for range ticker.C {
			cleanExpiredKeys()
		}
	}()
}

func initRedis() {
	redisURL := "redis://default:CrRppNmTZsmlBvFYGFpAKujvahhNMyxb@maglev.proxy.rlwy.net:47225"
	
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		fmt.Printf("❌ Failed to parse Redis URL: %v\n", err)
		return
	}
	
	redisClient = redis.NewClient(opt)
	
	// Test connection
	_, err = redisClient.Ping(ctx).Result()
	if err != nil {
		fmt.Printf("❌ Redis connection failed: %v\n", err)
		fmt.Println("⚠️  Countdown will use fallback value")
	} else {
		fmt.Println("✅ Redis connected successfully")
		
		// Initialize countdown if not exists
		initCountdown()
	}
}

func initCountdown() {
	exists, err := redisClient.Exists(ctx, "upd:cd").Result()
	if err != nil {
		fmt.Printf("❌ Failed to check Redis key: %v\n", err)
		return
	}
	
	if exists == 0 {
		// Set initial countdown dengan timestamp
		initialCountdown := COUNTDOWN_DAYS * 24 * 60 * 60 // dalam detik
		startTime := time.Now().Unix() // timestamp saat server start
		endTime := startTime + int64(initialCountdown)
		
		// Simpan end timestamp ke Redis
		err := redisClient.Set(ctx, "upd:cd", endTime, 0).Err()
		if err != nil {
			fmt.Printf("❌ Failed to initialize countdown: %v\n", err)
		} else {
			fmt.Printf("✅ Countdown initialized to %d days (ends at: %s)\n", 
				COUNTDOWN_DAYS, time.Unix(endTime, 0).Format("2006-01-02 15:04:05"))
		}
	} else {
		// Log current end time
		endTimeStr, err := redisClient.Get(ctx, "upd:cd").Result()
		if err != nil {
			fmt.Printf("❌ Failed to get countdown: %v\n", err)
		} else {
			endTime, _ := strconv.ParseInt(endTimeStr, 10, 64)
			remainingSeconds := calculateRemainingSeconds(endTime)
			days, hours, minutes, seconds := secondsToDHMS(remainingSeconds)
			
			fmt.Printf("📊 Current countdown: %d days %d hours %d minutes %d seconds\n", 
				days, hours, minutes, seconds)
		}
	}
}

func calculateRemainingSeconds(endTime int64) int64 {
	now := time.Now().Unix()
	remaining := endTime - now
	
	if remaining < 0 {
		return 0
	}
	return remaining
}

func secondsToDHMS(totalSeconds int64) (days, hours, minutes, seconds int64) {
	days = totalSeconds / (24 * 60 * 60)
	remainingSeconds := totalSeconds % (24 * 60 * 60)
	hours = remainingSeconds / (60 * 60)
	remainingSeconds %= 60 * 60
	minutes = remainingSeconds / 60
	seconds = remainingSeconds % 60
	
	return
}

func cleanExpiredKeys() {
	tempKeysLock.Lock()
	defer tempKeysLock.Unlock()
	
	now := time.Now()
	cleaned := 0
	
	for key, temp := range tempKeys {
		if temp.Expiry.Before(now) {
			delete(tempKeys, key)
			
			// Juga hapus dari API_KEYS
			keysMutex.Lock()
			delete(API_KEYS, key)
			keysMutex.Unlock()
			
			cleaned++
		}
	}
	
	if cleaned > 0 {
		fmt.Printf("[TEMP KEYS] 🗑️  Cleaned %d expired temporary keys\n", cleaned)
	}
}

func loadEnvFile() {
	file, err := os.Open(ENV_FILE)
	if err != nil {
		fmt.Printf("📄 No .env file found, using environment variables only\n")
		return
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	keysCount := 0
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		
		if strings.HasPrefix(key, "API_KEY") {
			if value != "" {
				API_KEYS[value] = true
				keysCount++
				fmt.Printf("✅ Loaded API key from .env: %s=***%s\n", 
					key, value[len(value)-4:]) 
			}
		}
	}
	
	if keysCount > 0 {
		fmt.Printf("📄 Loaded %d API keys from .env file\n", keysCount)
	}
}

func loadEnvVars() {
	envVars := os.Environ()
	keysCount := 0
	
	for _, envVar := range envVars {
		parts := strings.SplitN(envVar, "=", 2)
		if len(parts) != 2 {
			continue
		}
		
		key := parts[0]
		value := parts[1]
		
		if strings.HasPrefix(key, "API_KEY") {
			if value != "" {
				API_KEYS[value] = true
				keysCount++
				
				if !strings.Contains(strings.ToLower(key), "secret") {
					fmt.Printf("✅ Loaded API key from env: %s=***%s\n", 
						key, value[len(value)-4:])
				}
			}
		}
	}
	
	if keysCount > 0 {
		fmt.Printf("🌍 Loaded %d API keys from environment variables\n", keysCount)
	}
}

func reloadAPIKeys() {
	fmt.Println("🔄 Reloading API keys...")
	keysMutex.Lock()
	defer keysMutex.Unlock()
	
	API_KEYS = make(map[string]bool)
	
	loadEnvFile()
	loadEnvVars()
	
	fmt.Printf("✅ Reloaded %d API keys\n", len(API_KEYS))
}

func apiKeyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			apiKey = r.URL.Query().Get("api_key")
		}
		
		keyForLog := "not_provided"
		if apiKey != "" {
			if len(apiKey) > 4 {
				keyForLog = "***" + apiKey[len(apiKey)-4:]
			} else {
				keyForLog = "***"
			}
		}
		
		fmt.Printf("[AUTH] 🔑 Key provided: %s | Path: %s\n", keyForLog, r.URL.Path)
		
		keysMutex.RLock()
		_, valid := API_KEYS[apiKey]
		keysMutex.RUnlock()
		
		if !valid {
			fmt.Printf("[AUTH] ❌ Invalid API key: %s\n", keyForLog)
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"Unauthorized - Invalid API Key"}`, http.StatusUnauthorized)
			return
		}
		
		fmt.Printf("[AUTH] ✅ Authorized with key: %s\n", keyForLog)
		next(w, r)
	}
}

func generateFilename(originalName string) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

	const minLength = 4
	const maxLength = 6

	ext := filepath.Ext(originalName)

	rand.Seed(time.Now().UnixNano())
	length := rand.Intn(maxLength-minLength+1) + minLength

	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}

	return string(b) + ext
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := strings.Split(r.RemoteAddr, ":")[0]
	userAgent := r.UserAgent()
	fmt.Printf("[UPLOAD] 📥 Request from %s | Agent: %s\n", clientIP, userAgent)

	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		fmt.Printf("[UPLOAD] ❌ Method not allowed: %s\n", r.Method)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, MAX_UPLOAD_SIZE)
	if err := r.ParseMultipartForm(MAX_UPLOAD_SIZE); err != nil {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"File too large (max 20MB)"}`, http.StatusBadRequest)
		fmt.Printf("[UPLOAD] ❌ File too large: %v\n", err)
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"No file uploaded"}`, http.StatusBadRequest)
		fmt.Printf("[UPLOAD] ❌ No file uploaded: %v\n", err)
		return
	}
	defer file.Close()

	fmt.Printf("[UPLOAD] 📄 Processing: %s (%d bytes)\n", 
		handler.Filename, handler.Size)

	newFilename := generateFilename(handler.Filename)
	savePath := filepath.Join(UPLOAD_DIR, newFilename)
	
	if _, err := os.Stat(UPLOAD_DIR); os.IsNotExist(err) {
		os.MkdirAll(UPLOAD_DIR, 0755)
		fmt.Printf("[UPLOAD] 📁 Created directory: %s\n", UPLOAD_DIR)
	}
	
	out, err := os.Create(savePath)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"Failed to save file"}`, http.StatusInternalServerError)
		fmt.Printf("[UPLOAD] ❌ Failed to create file: %v\n", err)
		return
	}
	defer out.Close()

	written, err := io.Copy(out, file)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"Failed to write file"}`, http.StatusInternalServerError)
		fmt.Printf("[UPLOAD] ❌ Failed to write file: %v\n", err)
		return
	}

	absPath, _ := filepath.Abs(savePath)
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	host := r.Host
	fileURL := fmt.Sprintf("%s://%s/f/%s", scheme, host, newFilename)

	fmt.Printf("[UPLOAD] ✅ SUCCESS: %s → %s (%d bytes)\n", 
		handler.Filename, newFilename, written)
	fmt.Printf("         ├─ Path: %s\n", absPath)
	fmt.Printf("         └─ URL: %s\n", fileURL)

	w.Header().Set("Content-Type", "application/json")
	response := types.FileResponse{
    Success:  true,
    Filename: newFilename,
    URL:      fileURL,
    Size:     written,
    Original: handler.Filename,
  }
	json.NewEncoder(w).Encode(response)
}

func getMimeType(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	
	mimeTypes := map[string]string{
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".png":  "image/png",
		".gif":  "image/gif",
		".webp": "image/webp",
		".svg":  "image/svg+xml",
		".ico":  "image/x-icon",
		".mp4":  "video/mp4",
		".webm": "video/webm",
		".avi":  "video/x-msvideo",
		".mov":  "video/quicktime",
		".mkv":  "video/x-matroska",
		".mp3":  "audio/mpeg",
		".wav":  "audio/wav",
		".ogg":  "audio/ogg",
		".pdf":  "application/pdf",
		".zip":  "application/zip",
		".txt":  "text/plain",
		".json": "application/json",
		".xml":  "application/xml",
	}

	if mime, exists := mimeTypes[ext]; exists {
		return mime
	}
	return "application/octet-stream"
}

func filesHandler(w http.ResponseWriter, r *http.Request) {
	filename := strings.TrimPrefix(r.URL.Path, "/f/")
	if filename == "" || filename == "/f/" {
		http.Error(w, "Missing filename", http.StatusBadRequest)
		return
	}

	filename = filepath.Base(filename)
	filePath := filepath.Join(UPLOAD_DIR, filename)

	clientIP := strings.Split(r.RemoteAddr, ":")[0]
	fmt.Printf("[DOWNLOAD] 📥 Request for: %s from %s\n", filename, clientIP)

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fmt.Printf("[DOWNLOAD] ❌ File not found: %s\n", filename)
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("[DOWNLOAD] ❌ Failed to open: %s | Error: %v\n", filename, err)
		http.Error(w, "Failed to open file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	stat, _ := file.Stat()
	fileSize := stat.Size()

	fmt.Printf("[DOWNLOAD] ✅ Serving: %s (%d bytes)\n", filename, fileSize)

	mimeType := getMimeType(filename)

	w.Header().Set("Content-Type", mimeType)
	w.Header().Set("Cache-Control", "public, max-age=31536000")
	w.Header().Set("Accept-Ranges", "bytes")

	rangeHeader := r.Header.Get("Range")
	
	if rangeHeader == "" {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", fileSize))
		io.Copy(w, file)
		return
	}

	var start, end int64
	fmt.Sscanf(rangeHeader, "bytes=%d-%d", &start, &end)

	if end == 0 || end >= fileSize {
		end = fileSize - 1
	}

	contentLength := end - start + 1

	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, fileSize))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", contentLength))
	w.WriteHeader(http.StatusPartialContent)

	file.Seek(start, 0)
	io.CopyN(w, file, contentLength)
}

func countdownHandler(w http.ResponseWriter, r *http.Request) {
	// Default fallback value
	remainingSeconds := int64(COUNTDOWN_DAYS * 24 * 60 * 60)
	
	// Try to get from Redis
	if redisClient != nil {
		endTimeStr, err := redisClient.Get(ctx, "upd:cd").Result()
		if err == nil {
			endTime, _ := strconv.ParseInt(endTimeStr, 10, 64)
			remainingSeconds = calculateRemainingSeconds(endTime)
		}
	}
	
	// Calculate days, hours, minutes, seconds
	days, hours, minutes, seconds := secondsToDHMS(remainingSeconds)
	
	// Format output dengan format yang bersih
	output := fmt.Sprintf("%d hari %d jam %d menit %d detik", 
		days, hours, minutes, seconds)
	
	// Log request
	clientIP := strings.Split(r.RemoteAddr, ":")[0]
	fmt.Printf("[COUNTDOWN] 📊 Request from %s | Remaining: %d days %d hours %d minutes %d seconds\n", 
		clientIP, days, hours, minutes, seconds)
	
	// Set header dan kirim response
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Write([]byte(output))
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	files, err := os.ReadDir(UPLOAD_DIR)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Cannot read upload directory",
		})
		return
	}
	
	var totalSize int64
  var fileList []types.FileInfo
	
	for _, file := range files {
		info, _ := file.Info()
		totalSize += info.Size()
		
		fileList = append(fileList, types.FileInfo{
      Name:       file.Name(),
      Size:       info.Size(),
      SizeHuman:  fmt.Sprintf("%.2f MB", float64(info.Size())/(1024*1024)),
      Modified:   info.ModTime().Format("2006-01-02 15:04:05"),
      URL:        fmt.Sprintf("/f/%s", file.Name()),
    })
	}
	
	keysMutex.RLock()
	keysCount := len(API_KEYS)
	keysSample := []string{}
	count := 0
	for key := range API_KEYS {
		if count < 3 { 
			if len(key) > 8 {
				keysSample = append(keysSample, key[:4] + "..." + key[len(key)-4:])
			} else {
				keysSample = append(keysSample, "***")
			}
			count++
		}
	}
	keysMutex.RUnlock()
	
	response := types.StatsResponse{
    Status:          "ok",
    UploadDirectory: UPLOAD_DIR,
    TotalFiles:      len(fileList),
    TotalSize:       totalSize,
    TotalSizeHuman:  fmt.Sprintf("%.2f MB", float64(totalSize)/(1024*1024)),
    APIKeysCount:    keysCount,
    Files:           fileList,
    Timestamp:       time.Now().Format("2006-01-02 15:04:05"),
  }
	
	json.NewEncoder(w).Encode(response)
}

func reloadKeysHandler(w http.ResponseWriter, r *http.Request) {
	reloadAPIKeys()
	
	response := types.ReloadKeysResponse{
		Success:   true,
		Message:   "API keys reloaded",
		KeysCount: len(API_KEYS),
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func keysHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	switch r.Method {
	case "GET":
		keysMutex.RLock()
		keysCount := len(API_KEYS)
		keysMutex.RUnlock()
		
		response := types.ListKeysResponse{
      KeysCount: keysCount,
      Message:   "Use POST to add temporary keys or contact Admin",
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
		
	case "POST":
		key := r.FormValue("key")
		if key == "" {
			http.Error(w, `{"error":"Key parameter required"}`, http.StatusBadRequest)
			return
		}
		
		keysMutex.Lock()
		API_KEYS[key] = true
		keysCount := len(API_KEYS)
		keysMutex.Unlock()
		
		fmt.Printf("[KEYS] ➕ Added temporary API key: ***%s\n", key[len(key)-4:])
		
		response := types.AddKeyResponse{
      Success:   true,
      Message:   "Temporary key added!",
      KeysCount: keysCount,
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
		
	default:
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func tempKeyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if r.Method != http.MethodPost {
		response := types.ErrorResponse{
			Error: "Method not allowed",
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(response)
		return
	}
	
	// Generate 32 bytes random key seperti crypto.randomBytes(32) di Node.js
	keyBytes := make([]byte, 32)
	_, err := crand.Read(keyBytes)
	if err != nil {
		response := types.ErrorResponse{
			Error: "Failed to generate secure key",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		fmt.Printf("[TEMP KEYS] ❌ Failed to generate secure key: %v\n", err)
		return
	}
	
	// Encode ke hex (seperti Node.js buffer.toString('hex'))
	generatedKey := hex.EncodeToString(keyBytes) // 64 karakter hex
	expiry := time.Now().Add(15 * time.Minute)
	
	// Simpan key sementara
	tempKeysLock.Lock()
	tempKeys[generatedKey] = tempKey{
		Key:    generatedKey,
		Expiry: expiry,
	}
	
	// Tambahkan ke API_KEYS
	keysMutex.Lock()
	API_KEYS[generatedKey] = true
	keysCount := len(API_KEYS)
	keysMutex.Unlock()
	
	tempKeysLock.Unlock()
	
	// Log format yang aman (tampilkan 8 karakter terakhir)
	keyForLog := "***"
	if len(generatedKey) > 8 {
		keyForLog = "***" + generatedKey[len(generatedKey)-8:]
	} else if len(generatedKey) > 0 {
		keyForLog = "***" + generatedKey
	}
	
	fmt.Printf("[TEMP KEYS] ➕ Generated temporary key: %s (expires: %s)\n",
		keyForLog,
		expiry.Format("15:04:05"))
	
	// Juga tampilkan full key untuk keperluan debugging (opsional)
	if os.Getenv("DEBUG") == "true" {
		fmt.Printf("[TEMP KEYS] 🔍 DEBUG - Full key: %s\n", generatedKey)
	}
	
	response := types.TempKeyResponse{
		Success:    true,
		Key:        generatedKey,
		ExpiresIn:  "15 minutes",
		Expiry:     expiry.Format("2006-01-02 15:04:05"),
		Message:    "Temporary key generated successfully. Use in X-API-Key header.",
		Usage:      "This key will automatically expire after 15 minutes.",
		KeysCount:  keysCount,
		KeyLength:  len(generatedKey), // akan menjadi 64 karakter
		Bytes:      32,                // bytes asli sebelum encoding
	}
	
	json.NewEncoder(w).Encode(response)
}

func updScriptSendFileHandler(w http.ResponseWriter, r *http.Request) {
    filePath := "./public/assets/upd.script.js"
    
    file, err := os.Open(filePath)
    if err != nil {
        if os.IsNotExist(err) {
            http.Error(w, "JavaScript file not found", http.StatusNotFound)
        } else {
            http.Error(w, "Internal server error", http.StatusInternalServerError)
        }
        return
    }
    defer file.Close()
    
    fileInfo, err := file.Stat()
    if err != nil {
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    
    w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
    w.Header().Set("Content-Length", string(fileInfo.Size()))
    w.Header().Set("Cache-Control", "public, max-age=3600")
    
    _, err = io.Copy(w, file)
    if err != nil {
        http.Error(w, "Error sending file", http.StatusInternalServerError)
    }
}

func publicFileHandler(w http.ResponseWriter, r *http.Request) {
    cleanPath := filepath.Clean(r.URL.Path)
    
    workDir, _ := os.Getwd()
    publicDir := filepath.Join(workDir, "public")
    
    targetPath := filepath.Join(publicDir, cleanPath)

    info, err := os.Stat(targetPath)
    if err == nil && info.IsDir() {
        targetPath = filepath.Join(targetPath, "index.html")
    }

    if _, err := os.Stat(targetPath); os.IsNotExist(err) {
        fmt.Printf("🔍 Debug: File not found at %s\n", targetPath)
        http.NotFound(w, r)
        return
    }

    w.Header().Set("X-Content-Type-Options", "nosniff")
    w.Header().Set("Cache-Control", "no-store")
    
    http.ServeFile(w, r, targetPath)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	keysMutex.RLock()
	keysCount := len(API_KEYS)
	keysMutex.RUnlock()
	
	health := types.HealthResponse{
    Status:    "healthy",
    Service:   "tine-upd",
    Version:   "2.0",
    Timestamp: time.Now().Format("2006-01-02 15:04:05"),
    APIKeys:   keysCount,
    UploadDir: UPLOAD_DIR,
    MaxSizeMB: MAX_UPLOAD_SIZE / (1024 * 1024),
    Endpoints: []string{
        "POST /upload (with API key)",
        "GET  /files/{filename}",
        "GET  /files/cd (countdown)",
        "GET  /stats (with API key)",
        "GET  /health",
        "POST /addkey/temp (generate temp key)",
        "POST /keys/add (add temporary key)",
        "POST /keys/reload (reload from .env)",
    },
  }
	
	json.NewEncoder(w).Encode(health)
}

func main() {
	if err := os.MkdirAll(UPLOAD_DIR, 0755); err != nil {
		fmt.Printf("❌ Failed to create upload directory: %v\n", err)
	} else {
		absPath, _ := filepath.Abs(UPLOAD_DIR)
		fmt.Printf("📁 Upload directory: %s\n", absPath)
	}

	http.HandleFunc("/upload", apiKeyMiddleware(uploadHandler))
	http.HandleFunc("/stats", apiKeyMiddleware(statsHandler))
	http.HandleFunc("/keys/reload", apiKeyMiddleware(reloadKeysHandler))
	http.HandleFunc("/keys/add", keysHandler)
	http.HandleFunc("/addkey/temp", tempKeyHandler)
	
	http.HandleFunc("/f/", filesHandler)
	http.HandleFunc("/files/cd", countdownHandler)
	http.HandleFunc("/health", healthHandler)
	
	http.HandleFunc("/upd/script", updScriptSendFileHandler)
	http.HandleFunc("/", publicFileHandler)

	fmt.Println("=" + strings.Repeat("=", 60))
	fmt.Println("🚀 File Upload Server v2.0")
	fmt.Println("📌 Port:", PORT)
	fmt.Println("📁 Upload Directory:", UPLOAD_DIR)
	fmt.Println("🔑 API Keys Loaded:", len(API_KEYS))
	fmt.Println("💾 Max File Size:", MAX_UPLOAD_SIZE/(1024*1024), "MB")
	fmt.Println("🕐 Startup Time:", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println("=" + strings.Repeat("=", 60))

	fmt.Println("\n🔐 Authentication Methods:")
	fmt.Println("  • Header: X-API-Key: your_key")
	fmt.Println("  • Query: ?api_key=your_key")
	
	fmt.Println("\n📤 Upload: POST /upload (with API key)")
	fmt.Println("📥 Download: GET /f/{filename}")
	fmt.Println("⏰ Countdown: GET /files/cd")
	fmt.Println("📊 Stats: GET /stats (with API key)")
	fmt.Println("🔧 Manage Keys: POST /keys/add (add temporary key)")
	fmt.Println("🔑 Generate Temp Key: POST /addkey/temp (15 minutes expiry)")
	fmt.Println("🔄 Reload Keys: POST /keys/reload (reload from .env)")
	fmt.Println("❤️  Health: GET /health")
	fmt.Println()

	fmt.Println("Server is ready! Logs will appear below:")
	fmt.Println("-" + strings.Repeat("-", 60))

	if err := http.ListenAndServe(":"+PORT, nil); err != nil {
		fmt.Printf("❌ Server failed to start: %v\n", err)
	}
}

