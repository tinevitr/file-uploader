package types

type FileResponse struct {
	Success  bool   `json:"success"`
	Filename string `json:"filename"`
	URL      string `json:"url"`
	Size     int64  `json:"size"`
	Original string `json:"original"`
}

type HealthResponse struct {
    Status     string   `json:"status"`
    Service    string   `json:"service"`
    Version    string   `json:"version"`
    Timestamp  string   `json:"timestamp"`
    APIKeys    int      `json:"api_keys"`
    UploadDir  string   `json:"upload_dir"`
    MaxSizeMB  int      `json:"max_size_mb"`
    Endpoints  []string `json:"endpoints"`
}

type RootResponse struct {
	Service       string   `json:"service"`
	Version       string   `json:"version"`
	Features      []string `json:"features"`
	ContactAdmin  string   `json:"contactAdmin"`
	Documentation string   `json:"documentation"`
}

type FileInfo struct {
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	SizeHuman  string `json:"size_human"`
	Modified   string `json:"modified"`
	URL        string `json:"url"`
}

type StatsResponse struct {
	Status          string    `json:"status"`
	UploadDirectory string    `json:"upload_directory"`
	TotalFiles      int       `json:"total_files"`
	TotalSize       int64     `json:"total_size"`
	TotalSizeHuman  string    `json:"total_size_human"`
	APIKeysCount    int       `json:"api_keys_count"`
	Files           []FileInfo `json:"files"`
	Timestamp       string    `json:"timestamp"`
}

type AddKeyResponse struct {
	Success  bool   `json:"success"`
	Message  string `json:"message"`
	KeysCount int   `json:"keys_count"`
}

type ListKeysResponse struct {
	KeysCount int    `json:"keys_count"`
	Message   string `json:"message"`
}

type ReloadKeysResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	KeysCount int    `json:"keys_count"`
}

type TempKeyResponse struct {
	Success   bool   `json:"success"`
	Key       string `json:"key"`
	ExpiresIn string `json:"expires_in"`
	Expiry    string `json:"expiry"`
	Message   string `json:"message"`
	Usage     string `json:"usage"`
	KeysCount int    `json:"keys_count"`
	KeyLength int    `json:"key_length"`
	Bytes     int    `json:"bytes"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}


