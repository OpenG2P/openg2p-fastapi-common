from typing import Generic, TypeVar

_T = TypeVar("T")


class Holder(Generic[_T]):
    """
    Useful holder tool for passing mutable object across functions.
    Define a Holder object like:
    ```python
    a_holder = Holder[int](123)
    ```
    or
    ```python
    a_holder = Holder[int]()
    a_holder.set(123)
    ```
    and get using
    ```python
    a_holder.get(default=456)
    ```
    """

    def __init__(self, value: _T | None = None):
        super().__init__()
        self.value: _T | None = value

    def get(self, default: _T = None) -> _T | None:
        if self.value is None:
            return default
        return self.value

    def set(self, value: _T) -> "Holder":
        self.value = value
        return self


class HolderNonNull(Holder, Generic[_T]):
    """
    Useful holder tool for passing mutable non-null object across functions.
    Define a HolderNonNull object like:
      a_holder = HolderNonNull[int](123)
    and get using
      a_holder.get(default=456)
    """

    def __init__(self, value: _T):
        if value is None:
            raise ValueError("Holder value can't be null")
        super().__init__(value=value)

    def get(self) -> _T:
        return self.value

    def set(self, value: _T) -> "Holder":
        if value is None:
            raise ValueError("Holder value can't be null")
        return super().set(value)
