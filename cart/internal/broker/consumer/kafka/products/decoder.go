package products

import (
	"encoding/json"
)

type Decoder struct{}

func NewDecoder() *Decoder {
	return &Decoder{}
}

func (d *Decoder) Decode(msgValue []byte) (Event, error) {

	var event Event

	err := json.Unmarshal(msgValue, &event)
	if err != nil {
		return Event{}, err
	}

	return event, nil
}
