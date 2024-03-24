package resolver

import (
	"encoding/binary"
	"fmt"
	"github.com/miekg/dns"
)

func resolve(msg []byte) ([]string, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("invalid DNS message: too short")
	}

	var results []string

	questionsCount := binary.BigEndian.Uint16(msg[4:6])

	questions := msg[12:]

	for i := 0; i < int(questionsCount); i++ {
		var questionName string
		for {
			len := int(questions[0])
			questionName += string(questions[1 : len+1])
			questions = questions[len+1:]
			len = int(questions[0])
			if len == 0 {
				break
			}
			questionName += "."
		}
		questions = questions[1:]

		questionType := binary.BigEndian.Uint16(questions[0:2])
		questionClass := binary.BigEndian.Uint16(questions[2:4])

		questions = questions[4:]

		result := fmt.Sprintf("%s*%s*%s", questionName, dns.Type(questionType), dns.Class(questionClass))
		results = append(results, result)
	}
	return results, nil
}

/* func test() {
	dnsMsg := []byte{
		// Header
		0x00, 0x01, // transactionId
		0x00, 0x00, // flags
		0x00, 0x02, // questions
		0x00, 0x00, // answerRRs
		0x00, 0x00, // authorityRRs
		0x00, 0x00, // additionalRRs

		// Question 1
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01, 0x00, 0x01,
		// Question 2
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01, 0x00, 0x01,
	}

	resolve(dnsMsg)
}
*/
