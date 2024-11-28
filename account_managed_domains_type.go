package zoom

// AccountManagedDomains represents account managed domains
type AccountManagedDomains struct {
	TotalRecords int      `json:"total_records"`
	Domains      []Domain `json:"domains"`
}

type Domain struct {
	Domain string `json:"domain"`
	Status string `json:"status"`
}
