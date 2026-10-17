package protocol

import (
	"context"
	"fmt"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/stream"
)

// MaxAdSize bounds every ad read from a peer. The largest legitimate message
// carries one token, well under this.
const MaxAdSize = 64 * 1024

// Send writes v as one ClassAd message on st.
func Send(ctx context.Context, st *stream.Stream, v any) error {
	return SendAd(ctx, st, Encode(v))
}

// SendAd writes ad as one message on st.
func SendAd(ctx context.Context, st *stream.Stream, ad *classad.ClassAd) error {
	msg := message.NewMessageForStream(st)
	if err := msg.PutClassAd(ctx, ad); err != nil {
		return fmt.Errorf("encoding reply: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("sending reply: %w", err)
	}
	return nil
}

// RecvAd reads one ClassAd message from st.
func RecvAd(ctx context.Context, st *stream.Stream) (*classad.ClassAd, error) {
	msg := message.NewMessageFromStream(st)
	ad, err := msg.GetClassAdWithMaxSize(ctx, MaxAdSize)
	if err != nil {
		return nil, fmt.Errorf("reading message: %w", err)
	}
	return ad, nil
}

// Recv reads one message from st into v.
func Recv(ctx context.Context, st *stream.Stream, v any) error {
	ad, err := RecvAd(ctx, st)
	if err != nil {
		return err
	}
	return Decode(ad, v)
}
