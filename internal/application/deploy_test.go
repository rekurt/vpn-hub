package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"vpn-hub/internal/domain"
)

type deployRevisionStore struct {
	saveErr error
	saved   []string
}

func (s *deployRevisionStore) Save(_ context.Context, state domain.DesiredState) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.saved = append(s.saved, state.Revision)
	return nil
}

func (s *deployRevisionStore) Load(context.Context) (domain.DesiredState, error) {
	return domain.DesiredState{}, errors.New("no revision")
}

type deployConfirmations struct {
	armCalls  int
	armResult bool
	confirmed int
}

func (c *deployConfirmations) Arm(context.Context, time.Duration, string) (bool, error) {
	c.armCalls++
	return c.armResult, nil
}

func (c *deployConfirmations) Confirm() error {
	c.confirmed++
	return nil
}

// The compensation this test pins down: Arm ran but Save did not, so a pending
// confirmation would point at a revision that was never written and the agent
// would "roll back" onto the already active one at the deadline.
func TestApplyClearsTheArmWhenSaveFails(t *testing.T) {
	t.Parallel()
	saveErr := errors.New("disk full")
	confirmations := &deployConfirmations{armResult: true}
	deployment := Deployment{
		Service:       Service{RevisionStore: &deployRevisionStore{saveErr: saveErr}},
		Confirmations: confirmations,
	}

	_, err := deployment.Apply(context.Background(), domain.DesiredState{Revision: "abc"}, time.Minute)
	if !errors.Is(err, saveErr) {
		t.Fatalf("err = %v, want the save failure", err)
	}
	var stage DeployError
	if !errors.As(err, &stage) || stage.Stage != DeployStageSave {
		t.Fatalf("stage = %+v, want %q", err, DeployStageSave)
	}
	if confirmations.armCalls != 1 || confirmations.confirmed != 1 {
		t.Fatalf("arm=%d confirm=%d, want the arm compensated exactly once",
			confirmations.armCalls, confirmations.confirmed)
	}
}

func TestApplyReportsAFirstDeployAsUnarmed(t *testing.T) {
	t.Parallel()
	store := &deployRevisionStore{}
	confirmations := &deployConfirmations{armResult: false}
	deployment := Deployment{
		Service:       Service{RevisionStore: store},
		Confirmations: confirmations,
	}

	result, err := deployment.Apply(context.Background(), domain.DesiredState{Revision: "abc"}, time.Minute)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if result.Armed {
		t.Fatal("a first deploy has nothing to roll back onto, yet Armed is true")
	}
	if confirmations.confirmed != 0 {
		t.Fatal("nothing failed, yet the confirmation was cleared")
	}
	if len(store.saved) != 1 || store.saved[0] != "abc" {
		t.Fatalf("saved = %v, want the revision persisted once", store.saved)
	}
}

func TestApplyWithoutConfirmationNeverArms(t *testing.T) {
	t.Parallel()
	store := &deployRevisionStore{}
	confirmations := &deployConfirmations{}
	deployment := Deployment{
		Service:       Service{RevisionStore: store},
		Confirmations: confirmations,
	}

	result, err := deployment.Apply(context.Background(), domain.DesiredState{Revision: "abc"}, 0)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if confirmations.armCalls != 0 {
		t.Fatalf("arm was called %d times without --confirm-within", confirmations.armCalls)
	}
	if result.Armed {
		t.Fatal("Armed reported without a confirmation window")
	}
}
