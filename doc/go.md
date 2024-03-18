## Go Support


### Helpers

#### Packages and Aliases

Consider the following code:

```go
import (
	"fmt"

	fmt2 "fmt"
)


```

The `query.context.packages` contains the list of packages being imported. In the code above, it will contain a single element: `"fmt"`

The `query.context.packages_aliased` contains a map of the packages being imported with their aliases. If a package is not aliased, it will just contain it's value. For the code above, the map contains the following key/value:
 - "fmt" -> "fmt"
 - "fmt2" -> "fmt"


Let's now consider another code

```go
import (
	"errors"
	"fmt"
	"net/http"
)
```

- `query.context.packages` will contain the values `errors`, `fmt` and `net/http`
- `query.context.packages_aliased` will contain the following values
  - `errors` -> `errors`
  - `fmt` -> `fmt`
  - `http` -> `net/http`

