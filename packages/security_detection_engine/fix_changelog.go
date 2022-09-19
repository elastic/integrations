package main
 
import (
    "bufio"
    "fmt"
    "os"
    "regexp"
)
 
func main() {
 
    readFile, err := os.Open("changelog.yml")
  
    if err != nil {
        fmt.Println(err)
    }
    fileScanner := bufio.NewScanner(readFile)
 
    fileScanner.Split(bufio.ScanLines)
  
    var commentR = regexp.MustCompile(`^#`)
    var versionR = regexp.MustCompile(`^  version:`)
    var changesR = regexp.MustCompile(`^- changes:`)
    var descriptionR = regexp.MustCompile(`^    - description:`)
    var linkR = regexp.MustCompile(`^      link:`)
    var typeR = regexp.MustCompile(`^      type:`)
    var changesLine, descriptionLine, typeLine, linkLine []byte
 
    for fileScanner.Scan() {
        var line = fileScanner.Text()
        if commentR.MatchString(line) {
            fmt.Println(line)
	} else if versionR.MatchString(line) {
            fmt.Printf("-%s\n%s\n%s\n%s\n%s\n", 
            	line[1:],
                string(changesLine), 
                descriptionLine, 
		typeLine, 
		linkLine)
	    changesLine = nil
	    descriptionLine = nil
	    typeLine = nil
	    linkLine = nil
	} else if changesR.MatchString(line) {
            changesLine = append(changesLine, fmt.Sprintf(" %s",line[1:])...)
        } else if descriptionR.MatchString(line) {
            descriptionLine = append(descriptionLine, line...)
        } else if linkR.MatchString(line) {
            linkLine = append(linkLine, line...)
        } else if typeR.MatchString(line) {
            typeLine = append(typeLine, line...)
        }
    }
  
    readFile.Close()
}
