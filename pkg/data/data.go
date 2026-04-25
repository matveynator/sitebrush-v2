package Data

type Post struct {
	Id         int64
	OwnerId    int
	EditorId   int
	DeleterId  int
	RequestUri string
	Type       string
	Date       int64
	Title      string
	Body       string
	Header     string
	Summary    string
	ShortText  string
	Tags       string
	Revision   int
	Domain     string
	Status     string
	Published  bool
}

type Domain struct {
	Id              int64
	Name            string
	DNSZoneData     string
	CNAMESecret     string
	EmailSecretHash string
	Status          string
	Frozen          bool
}

type User struct {
	Id                 int64
	SessionId          string
	OldId              int64
	AvatarId           int64
	Email              string
	PasswordHash       string
	Nickname           string
	FirstName          string
	LastName           string
	Gender             string
	Phone              string
	DateOfRegistration int64
	DateOfBirth        int64
	LastVisitTime      int64
	GreenwichOffset    int
	Activated          string
	VerificationCode   string
	Domain             string
	Status             string
	Language           string
	CurrentIP          string
	Profile            string
	Preferences        string
	SecurityLog        string
	InvitedBy          string
	InvitesAmount      int
	QuotaBytes         string
	QuotaOriginals     string
	QuotaBytesUsed     int64
	QuotaOriginalsUsed int64
	AutoGrab           string
	DomainToGrab       string
}

type Group struct {
	Id      int64
	OwnerId int64
	Name    string
	Title   string
	Comment string
	Date    int64
	Status  string
	Domain  string
}

type UserGroup struct {
	UserId  int64
	GroupId int64
	Status  string
	Domain  string
}

type Redirect struct {
	Id     int64
	OldUri string
	NewUri string
	Date   int64
	Status string
	Domain string
}

type URIMap struct {
	Id     int64
	OldUri string
	NewUri string
	Date   int64
	Status string
	Domain string
}

type Media struct {
	Id           int64
	Type         string
	Hash         string
	OriginalHash string
	Format       string
	MimeType     string
	StoragePath  string
	Width        int
	Height       int
	Status       string
	Domain       string
	Day          int
	Date         int64
	SizesArray   string
	Rating       float64
	RatingCount  int
	RatingIP     string
	Views        int
	BytesUsed    int64
}

type Template struct {
	Id     int64
	Name   string
	Data   string
	Status string
	Domain string
}

type PostTemplate struct {
	PostId     int64
	TemplateId int64
	Status     string
	Domain     string
}

type Backup struct {
	Id            int64
	Domain        string
	Path          string
	Checksum      string
	Size          int64
	Format        string
	DownloadToken string
	CreatedAt     int64
	CompletedAt   int64
	Status        string
	Error         string
}
