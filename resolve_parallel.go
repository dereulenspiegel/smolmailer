package smolmailer

import (
	"errors"
	"io"
	"sync"
)

func resolveParallel[T io.Closer](rfs ...func() (T, error)) (T, error) {
	resChan := make(chan T, len(rfs))
	defer close(resChan)
	errChan := make(chan error, len(rfs))
	wg := &sync.WaitGroup{}
	waitChan := make(chan struct{}, 1)
	for _, rf := range rfs {
		wg.Add(1)
		go func(resChan chan T, errChan chan error, wg *sync.WaitGroup, rf func() (T, error)) {
			defer wg.Done()
			res, err := rf()
			if err != nil {
				// Try to write into the errChan, which might be closed already
				select {
				case errChan <- err:
				}
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
	go func(waitChan chan struct{}, errChan chan error, wg *sync.WaitGroup) {
		wg.Wait()
		close(waitChan)
		close(errChan)
	}(waitChan, errChan, wg)
	var res T
	select {
	case res = <-resChan:
		go func(resChan chan T) {
			for unusedRes := range resChan {
				// Close the unused results
				unusedRes.Close()
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
