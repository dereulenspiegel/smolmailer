package smolmailer

import (
	"errors"
	"io"
	"sync"
)

func resolveParallel[T io.Closer](rfs ...func() (T, error)) (T, error) {
	resChan := make(chan T, 1)
	defer close(resChan)
	errChan := make(chan error, len(rfs))
	wg := &sync.WaitGroup{}
	for _, rf := range rfs {
		wg.Add(1)
		go func(resChan chan T, errChan chan error, rf func() (T, error)) {
			defer wg.Done()
			res, err := rf()
			if err != nil {
				errChan <- err
				return
			}
			select {
			case resChan <- res:
				return
			default:
				res.Close()
			}
		}(resChan, errChan, rf)
	}
	wg.Wait()
	close(errChan)
	var res T
	select {
	case res = <-resChan:
		return res, nil
	default:
		errs := []error{}
		for err := range errChan {
			errs = append(errs, err)
		}
		return res, errors.Join(errs...)
	}
}
