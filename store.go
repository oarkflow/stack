package stack

import "sync"

// Storage interface for error storage and search
type Storage interface {
	Add(record *ErrorRecord)
	Get(id string) (*ErrorRecord, bool)
	SearchByDomain(domain Domain) []*ErrorRecord
	SearchBySeverity(severity Severity) []*ErrorRecord
	SearchByCode(code string) []*ErrorRecord
	SearchByStatus(status int) []*ErrorRecord
	SearchByUserID(userID string) []*ErrorRecord
	SearchByRequestID(requestID string) []*ErrorRecord
	Clear()
}

// ErrorStore implements the Storage interface using in-memory storage
type ErrorStore struct {
	records map[string]*ErrorRecord // Use map for storing records
	mu      sync.RWMutex
}

func NewErrorStore() *ErrorStore {
	return &ErrorStore{
		records: make(map[string]*ErrorRecord),
	}
}

func (idx *ErrorStore) Add(record *ErrorRecord) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.records[record.ID] = record
}

func (idx *ErrorStore) Get(id string) (*ErrorRecord, bool) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	record, exists := idx.records[id]
	return record, exists
}

func (idx *ErrorStore) SearchByDomain(domain Domain) []*ErrorRecord {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	var results []*ErrorRecord
	for _, record := range idx.records {
		if record.Domain == domain {
			results = append(results, record)
		}
	}
	return results
}

func (idx *ErrorStore) SearchBySeverity(severity Severity) []*ErrorRecord {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	var results []*ErrorRecord
	for _, record := range idx.records {
		if record.Severity == severity {
			results = append(results, record)
		}
	}
	return results
}

func (idx *ErrorStore) SearchByCode(code string) []*ErrorRecord {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	var results []*ErrorRecord
	for _, record := range idx.records {
		if record.Code == code {
			results = append(results, record)
		}
	}
	return results
}

func (idx *ErrorStore) SearchByStatus(status int) []*ErrorRecord {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	var results []*ErrorRecord
	for _, record := range idx.records {
		if record.Status == status {
			results = append(results, record)
		}
	}
	return results
}

func (idx *ErrorStore) SearchByUserID(userID string) []*ErrorRecord {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	var results []*ErrorRecord
	for _, record := range idx.records {
		if record.UserID == userID {
			results = append(results, record)
		}
	}
	return results
}

func (idx *ErrorStore) SearchByRequestID(requestID string) []*ErrorRecord {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	var results []*ErrorRecord
	for _, record := range idx.records {
		if record.RequestID == requestID {
			results = append(results, record)
		}
	}
	return results
}

func (idx *ErrorStore) Clear() {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.records = make(map[string]*ErrorRecord)
}
