package yaoyaola

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"net/http"
	netUrl "net/url"
	"strconv"
	"time"
)

const (
	RedPocketTypePersonal RedPocketType = iota
	RedPocketTypeEnterprise
)

const (
	apiPrefix = "https://www.yaoyaola.net/exapi"
)

type (
	Client struct {
		uid    string
		apiKey string
	}

	AccountInfo struct {
		Balance   string `json:"balance"`   // remaining red pocket money that can be sent
		ExpiredAt Time   `json:"apiexpire"` // account expiration date/time
	}

	RedPocket struct {
		// Defaults to RedPocketTypePersonal (user must click a red
		// pocket to receive)
		// RedPocketTypeEnterprise (user receives red pocket
		// automatically, allowed to send red pocket over 200 yuan)
		Type RedPocketType

		// Money in cents of a red pocket, must not be less than 30
		// (0.3 yuan)
		Cents int

		// Once SendRedPocket() with RedPocketTypePersonal succeeds,
		// you'll receive a new Wechat message like this:
		//  你参与{Title}，成功获得{SenderName}赠送的红包，
		//  点击消息打开，一起抢红包、拼手气吧！
		//  点击消息拆开红包即可获得现金
		// And on the details page, you'll see:
		//  {SenderName}的红包
		//  {Description}
		// If the red pocket type is RedPocketTypeEnterprise, only
		// Description is used
		Title       string
		Description string
		SenderName  string

		// Open ID of the user who receives a red pocket, can be
		// obtained by the redirection URL from GetAuthURL
		ReceiverOpenId string

		// If Order ID is empty, random string will be used
		OrderId string
	}

	RedPocketType int

	Time struct {
		time.Time
	}

	UserInfo struct {
		OpenId   string `json:"openid"`
		NickName string `json:"nickname"`
		ImageUrl string `json:"headimgurl"`
	}

	Error struct {
		Code    string `json:"errcode"`
		Message string `json:"errmsg"`
	}
)

func (t *Time) UnmarshalJSON(b []byte) error {
	str, err := strconv.Unquote(string(b))
	if err != nil {
		return err
	}
	locaiton := time.FixedZone("UTC+8", 8*60*60)
	tm, err := time.ParseInLocation("2006-01-02 15:04:05", str, locaiton)
	if err != nil {
		return err
	}
	*t = Time{tm}
	return nil
}

func (e Error) Error() string {
	return "Error #" + e.Code + ": " + e.Message
}

// NewClient creates a new client from UID and API key.
func NewClient(uid, apiKey string) *Client {
	return &Client{
		uid:    uid,
		apiKey: apiKey,
	}
}

// GetAuthURL generates authorization URL. Visit this URL in Wechat to get
// user's Open ID. To get user's name and image, set getUserInfo to true. Open
// ID and user info will be added as query string to the redirect URL provided.
// The URL can be verified by VerifyURL().
func (c Client) GetAuthURL(redirect string, getUserInfo bool) string {
	values := netUrl.Values{}
	values.Set("url", redirect)
	if getUserInfo {
		values.Set("flag", "1")
	} else {
		values.Set("flag", "0")
	}
	return apiPrefix + "/check_user/" + c.uid + "?" + values.Encode()
}

// VerifyURL verifies the rediection URL from yaoyaola and, if URL is valid,
// returns the Open ID and user info (present if GetAuthURL's getUserInfo is
// true).
func (c Client) VerifyURL(url string) (openId string, userInfo UserInfo, ok bool) {
	u, err := netUrl.Parse(url)
	if err != nil {
		return
	}
	query, err := netUrl.ParseQuery(u.RawQuery)
	if err != nil {
		return
	}
	strToSign := c.apiKey + query.Get("openid") + query.Get("ivtick")
	hash := md5.Sum([]byte(strToSign))
	sign := hex.EncodeToString(hash[:])
	if sign != query.Get("encdata") {
		return
	}
	openId = query.Get("openid")
	userInfo.OpenId = openId
	if ui := query.Get("userinfo"); ui != "" {
		if decoded, berr := base64.StdEncoding.DecodeString(ui); berr == nil {
			json.Unmarshal(decoded, &userInfo)
		}
	}
	ok = true
	return
}

// GetAccountInfo gets balance and expiration date of current account.
func (c Client) GetAccountInfo(ctx context.Context) (*AccountInfo, error) {
	values := netUrl.Values{}
	values.Set("uid", c.uid)
	var info AccountInfo
	err := c.request(ctx, "/accountinfo", values, &info)
	if err != nil {
		return nil, err
	}
	return &info, nil
}

// SendRedPocket sends a Wechat red pocket.
func (c Client) SendRedPocket(ctx context.Context, redPocket RedPocket) error {
	return c.request(ctx, "/SendRedPackToOpenid", c.redPocketQuery(redPocket), nil)
}

func (c Client) request(ctx context.Context, path string, params netUrl.Values, target interface{}) error {
	req, err := http.NewRequestWithContext(ctx, "GET", apiPrefix+path+"?"+params.Encode(), nil)
	if err != nil {
		return err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	var respError Error
	json.Unmarshal(b, &respError)
	if respError.Code != "" && respError.Code != "0" {
		return respError
	}
	if target == nil {
		return nil
	}
	return json.Unmarshal(b, target)
}

func (c Client) redPocketQuery(redPocket RedPocket) netUrl.Values {
	uid := c.uid
	typ := strconv.Itoa(int(redPocket.Type))
	orderid := redPocket.OrderId
	if orderid == "" {
		orderid = randomString(20)
	}
	money := strconv.Itoa(redPocket.Cents)
	reqtick := strconv.FormatInt(time.Now().Unix(), 10)
	openid := redPocket.ReceiverOpenId
	strToSign := uid + typ + orderid + money + reqtick + openid + c.apiKey
	hash := md5.Sum([]byte(strToSign))
	sign := hex.EncodeToString(hash[:])
	values := netUrl.Values{}
	values.Set("uid", uid)
	values.Set("type", typ)
	values.Set("orderid", orderid)
	values.Set("money", money)
	values.Set("reqtick", reqtick)
	values.Set("openid", openid)
	values.Set("title", redPocket.Title)
	values.Set("wishing", redPocket.Description)
	values.Set("sendname", redPocket.SenderName)
	values.Set("sign", sign)
	return values
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}
