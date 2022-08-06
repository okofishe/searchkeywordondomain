package main

import (
	"bufio"
	"fmt"
	emailverifier "github.com/AfterShip/email-verifier"
	"github.com/bobesa/go-domain-util/domainutil"
	"math/rand"

	//"strconv"
	//"unicode"

	//"github.com/bradhe/stopwatch"
	"github.com/cheggaaa/pb"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"

	"strings"
)
var success []string
var success_Email[]string
var stringByte string
var stringByte2 string
var substring []string
//var t string
var saveFileName string
var count int
var mut sync.Mutex
const xthreads = 25 // Total number of threads to use, excluding the main() thread
var (
	verifier = emailverifier.NewVerifier()
)
var dats []string
var f string
var datsRemoveEmail []string

func main() {

	if (len(os.Args) < 3 || len(os.Args) > 4) {
		fmt.Println("Missing parameter, provide file names in .txt and keyword as string e.g program.exe sites.txt keyword,MAXIMUM OF 2 KEYWORDS")
		os.Exit(1)
	}

	if len(os.Args) == 3 {
		f = os.Args[1]
		substring=[]string{os.Args[2]}
	}
	if len(os.Args) == 4 {
		f = os.Args[1]
		substring=[]string{os.Args[2],os.Args[3]}
	}

	fmt.Println("#################################################################################################")
	fmt.Println("Check given keyword against domains on given emails to see if keyword(s) is present in domain")
	fmt.Println("Save the result into a file with _emailmarketing extension")
	fmt.Println("###################################################################################################")

	saveFileName=strings.Join(substring,"")
	rand.Seed(time.Now().UnixNano())
	saveFileName=saveFileName+"-"+randSeq(5)+"_betterkeyword.txt"
	dat, err := ioutil.ReadFile(f)
	if err != nil {
		log.Fatal(err)
	}
	dats = strings.Split(strings.TrimSuffix(string(dat), "\n"), "\r\n")
	dats=removeDuplicateStr(dats) 	//remove duplicate strings
	lc, err := lineCount(f)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Input file name: ",f)
	fmt.Println("Keyword being search for",substring)
	fmt.Println("Total Number of email is  :", lc)
	var ch = make(chan string, lc) // This number 50 can be anything as long as it's larger than xthreads
	var wg sync.WaitGroup
	// Now the jobs can be added to the channel, which is used as a queue
	for _,buff:=range dats{
		ch <- buff
	}
	//watch := stopwatch.Start()
	bar := pb.StartNew(int(lc))



		wg.Add(xthreads)
		for i := 0; i < xthreads; i++ {

			go func() {
				for {
					a, ok := <-ch
					if !ok { // if there is nothing to do and the channel has been closed then end the goroutine
						wg.Done()
						return
					}
					bar.Increment()
					dowork(a) // do the thing
				}
			}()
		}

	close(ch) // This tells the goroutines there's nothing else to do
	wg.Wait() // Wait for the threads to finish
	bar.FinishPrint("Done")
	stringByte := strings.Join(datsRemoveEmail, "\r\n")
	err = ioutil.WriteFile(f, []byte(stringByte), 0644)
	if err != nil {
		log.Fatalf("could not write file: %v", err)
	}
	fmt.Println("Total Number of Saved email is  :", count)
	fmt.Println("Output file name for filter emails",saveFileName)
	//fmt.Printf("Millseconds elapsed: %v\n", watch.Milliseconds())
}





func dowork(email string){


	ret, err := verifier.Verify(email)
	if err != nil {
		//fmt.Println("verify email address failed, error is: ", err)
		//delete email from array and return
		datsRemoveEmail = removeEmailFromArray(dats, email)
		return
	}
	if !ret.Syntax.Valid {
		//fmt.Println("email address syntax is invalid")
		//delete email from array and return
		datsRemoveEmail = removeEmailFromArray(dats, email)
		return
	}
	if !ret.HasMxRecords{
		datsRemoveEmail = removeEmailFromArray(dats, email)
		return
	}
	if ret.Free{
		//delete email from array and return
		datsRemoveEmail = removeEmailFromArray(dats, email)
		return
	}


	//remove double domain from email list
	email=strings.ToLower(email)
	unwantedemail:=false
	list := []string{"policy","catalog","web","help","gov", "edu", "org", "fbi", "police", "admin", "postmaster", "webmaster", "staples",
		"press", "abuse", "security", "hostmaster", "helps", "ebay", "paypal", "help", "staples", "amazon", "microsoft",
		"donotreply", "jobs", "billing", "domain", "help", "apple", "privacy", "notes", "copyrights", "advertising","yahoo",
		"gmail","aol","hotmail","outlook","msn","malwarebytes.com"}
	//check if email consist of unwanted substring
	for _, sub := range list {
		if strings.Contains(email, sub) {
			unwantedemail = true
			break
		}
	}
	if unwantedemail {
		datsRemoveEmail = removeEmailFromArray(dats, email)
		return
	}
	emailRegexp := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	//validate email if it is a legal email address
	if !emailRegexp.MatchString(email) {
		datsRemoveEmail = removeEmailFromArray(dats, email)
		return
	}

	//split the email address
	components := strings.Split(email, "@")
	domain:=components[1]
	//user :=components[0]

	sub :=domainutil.HasSubdomain(domain)
	if sub ==true{
		datsRemoveEmail = removeEmailFromArray(dats, email)
		return
	}

	//search for domain inside slice for duplicate domain ie send only to one domain e.g if you have a@mac.com and b@mac.com,only a@mac.com will be process
	var result bool = false
	for _, x := range success {
		if x == domain {
			result = true
			break
		}
	}

	//domain not in slice then add to success
	if result==false{
		success=append(success,domain)
		stringByte = strings.Join(success, "\r\n")

		//test if keyword is in domain
		validdomain := domainutil.DomainSuffix(domain)
		if validdomain != "com" && validdomain != "us" {
			return
		}
		// Create HTTP client with timeout
		client := &http.Client{
			Timeout: 5 * time.Second,
		}

		// Make HTTP GET request
		response, err := client.Get("http://www."+domain)
		if err != nil {
			//fmt.Println(err)
			return
		}
		defer response.Body.Close()

		// Get the response body as a string
		dataInBytes, err := ioutil.ReadAll(response.Body)
		if err != nil {
			//fmt.Println(err)
			return
		}
		pageContent := string(dataInBytes)

		// Find a substr e.g mouse inside the domain body e.g macmall.com
		var sub string
		for _,sub=range substring {
			titleStartIndex := strings.Index(pageContent, sub)
			if titleStartIndex !=-1 {
				break
			}
			if titleStartIndex == -1 {
				//fmt.Printf("  No list of keyword substring %s found \n", substring)
				return
			}

		}
		//fmt.Printf("  substring %s found \n",sub)
		//save the email
		// If the file doesn't exist, create it, or append to the file
		success_Email =append(success_Email,email)
		stringByte2 = strings.Join(success_Email, "\r\n")
		mut.Lock()
		count++

		err = ioutil.WriteFile(saveFileName, []byte(stringByte2), 0644)
		mut.Unlock()
		if err != nil {
			//mut.Unlock()
			log.Fatal(err)
		}

	}

}


var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func removeDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

func removeEmailFromArray(s []string, r string) []string {
	for i, v := range s {
		if v == r {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}

func lineCount(filename string) (int64, error) {
	lc := int64(0)
	f, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		lc++
	}
	return lc, s.Err()
}