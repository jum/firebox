package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
)

const (
	chevron          = "»"
	PwSafeTimeFormat = "2006/01/02 15:04:05"
	DEBUG            = true
)

type PwIndex int

const (
	PwTitle PwIndex = iota
	PwUser
	PwPass
	PwURL
	PwCreated
	PwModified
	PwRecModified
	PwPolicy
	PwPolicyName
	PwHistory
	PwEMail
	PwSymbols
	PwNotes
	PwNumFields
)

var (
	fname        = flag.String("fname", "Firebox Export.csv", "Firebox export file name")
	outname      = flag.String("outname", "pwsafe_test.csv", "pwsafe import file name")
	PwsafeHeader = []string{"Group/Title", "Username", "Password", "URL", "Created Time", "Password Modified Time", "Record Modified Time", "Password Policy", "Password Policy Name", "History", "e-mail", "Symbols", "Notes"}
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(2)
	}
	flag.Parse()
	f, err := os.Open(*fname)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	cf := csv.NewReader(f)
	cf.FieldsPerRecord = -1
	recs, err := cf.ReadAll()
	if err != nil {
		panic(err)
	}
	if DEBUG {
		table := tablewriter.NewWriter(os.Stdout)
		table.AppendBulk(recs)
		table.Render()
	}
	out, err := os.Create(*outname)
	if err != nil {
		panic(err)
	}
	defer out.Close()
	outcsv := csv.NewWriter(out)
	err = outcsv.Write(PwsafeHeader)
	if err != nil {
		panic(err)
	}
	var current []string
	var curRev map[string]int
	//[]string{"Kennwörter", "Kontoname", "Webseite", "System", "Benutzer ID", "Kennwort", "Notes"}
	//[]string{"Bank", "Kontoname", "Bank/Filiale", "Konto Nr.", "Kennwort/PIN", "Bankleitzahl", "IBAN", "Limit", "Notes"}
	//[]string{"WLAN Keys", "SSID", "Password", "Notes"}
	//[]string{"Kreditkarten", "Kartentyp", "Kartennummer", "Gültig bis", "Karteninhaber", "PIN", "CVV", "Limit", "Tel. Verlust", "Tel. Service", "Webseite", "Notes"}
	//[]string{"Seriennummern", "Programm", "Seriennummer", "URL", "Notes"}
	var table *tablewriter.Table
	if DEBUG {
		table = tablewriter.NewWriter(os.Stdout)
		table.Append(PwsafeHeader)
	}
	for _, rec := range recs {
		if len(rec[0]) > 0 {
			current = rec
			curRev = revMap(current)
		} else {
			outrec := make([]string, PwNumFields)
			tstamp := time.Now().Format(PwSafeTimeFormat)
			outrec[PwCreated] = tstamp
			outrec[PwModified] = tstamp
			outrec[PwRecModified] = tstamp
			outrec[PwNotes] = rec[curRev["Notes"]]
			var title string
			switch current[0] {
			case "Kennwörter":
				title = rec[curRev["Kontoname"]]
				outrec[PwUser] = rec[curRev["Benutzer ID"]]
				sys := rec[curRev["System"]]
				if len(sys) > 0 {
					if len(outrec[PwUser]) > 0 {
						outrec[PwUser] += "@" + sys
					} else {
						outrec[PwUser] = sys
					}
				}
				outrec[PwURL] = rec[curRev["Webseite"]]
				outrec[PwPass] = rec[curRev["Kennwort"]]
				if len(title) == 0 {
					title = outrec[PwURL]
				}
				if len(outrec[PwUser]) == 0 {
					outrec[PwUser] = outrec[PwURL]
				}
			case "Bank":
				title = rec[curRev["Kontoname"]] + "@" + rec[curRev["Bank/Filiale"]]
				outrec[PwUser] = rec[curRev["Konto Nr."]]
				outrec[PwPass] = rec[curRev["Kennwort/PIN"]]
				outrec[PwURL] = rec[curRev["Webseite"]]
				for _, field := range []string{"Bankleitzahl", "IBAN", "Limit"} {
					val := rec[curRev[field]]
					if len(val) > 0 {
						outrec[PwNotes] = appendNote(outrec[PwNotes], fmt.Sprintf("%v: %v", field, val))
					}
				}
			case "Kreditkarten":
				title = rec[curRev["Kartentyp"]]
				outrec[PwUser] = rec[curRev["Kartennummer"]]
				outrec[PwPass] = rec[curRev["PIN"]]
				outrec[PwURL] = rec[curRev["Webseite"]]
				for _, field := range []string{"Gültig bis", "Karteninhaber", "CVV", "Limit", "Tel. Verlust", "Tel. Service"} {
					val := rec[curRev[field]]
					if len(val) > 0 {
						outrec[PwNotes] = appendNote(outrec[PwNotes], fmt.Sprintf("%v: %v", field, val))
					}
				}
			case "Seriennummern":
				title = rec[curRev["Programm"]]
				outrec[PwUser] = title
				outrec[PwPass] = rec[curRev["Seriennummer"]]
				outrec[PwURL] = rec[curRev["URL"]]
			case "WLAN Keys":
				title = rec[curRev["SSID"]]
				outrec[PwUser] = title
				outrec[PwPass] = rec[curRev["Password"]]
			}
			title = strings.Replace(title, ",", ";", -1)
			outrec[PwTitle] = current[0] + "." + strings.Replace(title, ".", chevron, -1)
			if len(outrec[PwNotes]) == 0 {
				outrec[PwNotes] = " "
			}
			if len(outrec[PwPass]) == 0 {
				outrec[PwPass] = "empty"
			}
			outrec[PwNotes] = strings.Replace(outrec[PwNotes], "\n", chevron, -1)
			if DEBUG {
				table.Append(outrec)
			}
			err := outcsv.Write(outrec)
			if err != nil {
				panic(err)
			}
		}
	}
	outcsv.Flush()
	if DEBUG {
		table.Render()
	}
}

func revMap(rec []string) (res map[string]int) {
	res = make(map[string]int)
	for i := range rec {
		res[rec[i]] = i
	}
	return
}

func appendNote(note, val string) string {
	if len(note) == 0 {
		return val
	}
	if note[len(note)-1] == '\n' {
		return note + val + "\n"
	}
	return note + "\n" + val + "\n"
}
