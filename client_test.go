package yaoyaola

import (
	"context"
	"os"
	"testing"
)

var (
	UID     = os.Getenv("YAOYAOLA_UID")
	API_KEY = os.Getenv("YAOYAOLA_API_KEY")
	client  = NewClient(UID, API_KEY)
)

func TestGetAuthURL(t *testing.T) {
	url := client.GetAuthURL("https://example.com/?foo=bar", false)
	if url != "https://www.yaoyaola.net/exapi/check_user/"+UID+"?flag=0&url=https%3A%2F%2Fexample.com%2F%3Ffoo%3Dbar" {
		t.Error("wrong auth url")
	}
}

func TestVerifyURL(t *testing.T) {
	openId, userInfo, ok := client.VerifyURL("https://github.com/caiguanhao?ivtick=1639992782&u_openid=odTNwwRVoxp3uaySbkfto7tRPo9I&openid=odTNwwRVoxp3uaySbkfto7tRPo9I&encdata=69257427bf913524278c8cc1db785ee4&userinfo=")
	if ok != true {
		t.Error("ok should be true")
	} else if openId == "" {
		t.Error("open id should not be empty")
	} else if userInfo.OpenId != openId {
		t.Error("user info's open id should equal to open id")
	}
}

func TestGetAccountInfo(t *testing.T) {
	info, err := client.GetAccountInfo(context.Background())
	if err == nil {
		t.Logf("Account info: %+v\n", *info)
	} else {
		t.Error(err)
	}
}

func TestSendRedPocket(t *testing.T) {
	openId := os.Getenv("YAOYAOLA_OPENID")
	if openId == "" {
		t.Log("To test SendRedPocket, provide environment variable YAOYAOLA_OPENID")
		return
	}
	rp := RedPocket{
		Type:           RedPocketTypeEnterprise,
		Cents:          30,
		Title:          "测试",
		Description:    "测试红包",
		SenderName:     "CGH",
		ReceiverOpenId: openId,
	}
	err := client.SendRedPocket(context.Background(), rp)
	if err == nil {
		t.Log("successfully sent a red pocket")
	} else {
		t.Error(err)
	}
}
