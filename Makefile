download:
  @echo Download go.mod dependencies
  @go mod download
 
# Shouldn't be necessary any more
# install-tools: download
#   @echo Installing tools from tools.go
#   @cat tools.go | grep _ | awk -F'"' '{print $$2}' | xargs -tI % go install %