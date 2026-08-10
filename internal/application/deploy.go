package application

import (
	"context"
	"time"

	"vpn-hub/internal/domain"
	"vpn-hub/internal/ports"
)

// Deployment is the deploy pipeline both hubctl and the bot drive: validate,
// drop revoked devices, compile the revision, then arm the confirmation safety
// net and persist -- in that order, with the same compensation. It exists once so
// the two operator seats cannot drift apart in the part that decides what the
// agent converges on.
type Deployment struct {
	Service       Service
	Revocations   ports.RevocationSource
	Confirmations ports.DeployConfirmation
}

// Compile validates, removes revoked devices and builds the desired state. The
// returned list holds the revoked ids that were excluded, for the caller to
// report in its own voice.
func (d Deployment) Compile(ctx context.Context) (domain.DesiredState, []string, error) {
	cfg, err := d.Service.LoadAndValidate(ctx)
	if err != nil {
		return domain.DesiredState{}, nil, err
	}
	// Applied after validation and before compiling the revision, so a revoked
	// device never reaches the state the agent converges on.
	revoked, err := d.Revocations.Load(ctx)
	if err != nil {
		return domain.DesiredState{}, nil, err
	}
	state, err := d.Service.BuildDesiredState(RemoveRevoked(cfg, revoked))
	return state, revoked, err
}

// DeployResult reports what Apply did.
type DeployResult struct {
	Revision string
	// Armed is false either because no confirmation was asked for, or because this
	// is the first deploy and there is no earlier revision to return to. Callers
	// must say so plainly: an operator who believes a rollback is watching when
	// none is armed is worse off than one who knows there is none.
	Armed bool
}

// DeployStage names the step of Apply that failed.
type DeployStage string

const (
	DeployStageArm  DeployStage = "arm"
	DeployStageSave DeployStage = "save"
)

// DeployError carries which step of Apply failed. Its message is the underlying
// error's own, so a caller that does not care renders exactly what it always did.
type DeployError struct {
	Stage DeployStage
	Err   error
}

func (e DeployError) Error() string { return e.Err.Error() }
func (e DeployError) Unwrap() error { return e.Err }

// Apply arms the rollback when confirmWithin > 0, then saves the revision.
func (d Deployment) Apply(ctx context.Context, state domain.DesiredState, confirmWithin time.Duration) (DeployResult, error) {
	armed := false
	if confirmWithin > 0 {
		var err error
		if armed, err = d.Confirmations.Arm(ctx, confirmWithin, state.Revision); err != nil {
			return DeployResult{}, DeployError{Stage: DeployStageArm, Err: err}
		}
	}
	if err := d.Service.Save(ctx, state); err != nil {
		// Arm ran but Save did not: a pending confirmation now points at a revision
		// that was never written, and the agent would "roll back" to the already
		// active one at the deadline. Clear it so nothing is armed over nothing.
		if armed {
			_ = d.Confirmations.Confirm()
		}
		return DeployResult{}, DeployError{Stage: DeployStageSave, Err: err}
	}
	return DeployResult{Revision: state.Revision, Armed: armed}, nil
}
