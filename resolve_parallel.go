package smolmailer

import (
	"errors"
	"io"
	"reflect"
	"sync"
)

func resolveParallel[T io.Closer](rfs ...func() (T, error)) (T, error) {
	resChan := make(chan T, len(rfs))
	errChan := make(chan error, len(rfs))
	wg := &sync.WaitGroup{}
	waitChan := make(chan struct{}, 1)
	for _, rf := range rfs {
		wg.Add(1)
		go func(resChan chan T, errChan chan error, wg *sync.WaitGroup, rf func() (T, error)) {
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
		}(resChan, errChan, wg, rf)
	}
	go func(waitChan chan struct{}, errChan chan error, resChan chan T, wg *sync.WaitGroup) {
		wg.Wait()
		close(waitChan)
		close(errChan)
		close(resChan)
	}(waitChan, errChan, resChan, wg)
	var res T
	select {
	case res = <-resChan:
		go func(resChan chan T) {
			for unusedRes := range resChan {
				if !isNil(unusedRes) {
					// Close the unused results
					unusedRes.Close()
				}
			}
		}(resChan)

		return res, nil
	case <-waitChan:
		//Wait chan is now closed, we didn't got a result
		errs := []error{}
		for err := range errChan {
			errs = append(errs, err)
		}
		return res, errors.Join(errs...)
	}
}

func isNil[T any](t T) bool {
	v := reflect.ValueOf(t)
	kind := v.Kind()
	// Must be one of these types to be nillable
	return (kind == reflect.Ptr ||
		kind == reflect.Interface ||
		kind == reflect.Slice ||
		kind == reflect.Map ||
		kind == reflect.Chan ||
		kind == reflect.Func) &&
		v.IsNil()
}
