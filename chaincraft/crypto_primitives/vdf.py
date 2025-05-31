# crypto_primitives/vdf.py


class VDFPrimitive:
    """
    Sloth Verifiable Delay Function implementation.

    This is a simple VDF based on iterative modular square roots.
    - Generation requires sequential computation (slow)
    - Verification can be done with modular squaring (fast)
    """

    def __init__(self, iterations=10000):
        """
        Initialize with a number of iterations (delay factor).

        Args:
            iterations: Number of sequential operations to perform
        """
        self.iterations = iterations
        # Large prime number for modular operations
        self.p = 64106875808534963770974826322234655855469213855659218736479077548818158667371

    def quad_res(self, x, p):
        """
        Check if x is a quadratic residue modulo p.

        Args:
            x: The number to check
            p: The prime modulus

        Returns:
            True if x is a quadratic residue modulo p
        """
        return pow(x, (p - 1) // 2, p) == 1

    def mod_sqrt_op(self, x, p):
        """
        Compute modular square root.

        Args:
            x: Input value
            p: Prime modulus

        Returns:
            Square root of x modulo p
        """
        if self.quad_res(x, p):
            y = pow(x, (p + 1) // 4, p)
        else:
            x = (-x) % p
            y = pow(x, (p + 1) // 4, p)
        return y

    def create_proof(self, input_data):
        """
        Create VDF proof by sequential modular square root operations.

        Args:
            input_data: Input string or value to use as seed

        Returns:
            The proof value after iterations
        """
        # Convert input to integer if it's a string
        if isinstance(input_data, str):
            x = int.from_bytes(input_data.encode(), "big")
        else:
            x = input_data

        # Apply modulo p to ensure x is in the correct range
        x = x % self.p

        # Perform sequential operations
        for _ in range(self.iterations):
            x = self.mod_sqrt_op(x, self.p)

        return x

    def verify_proof(self, input_data, proof):
        """
        Verify a VDF proof by repeated squaring.

        Args:
            input_data: Original input value or string
            proof: The proof value to verify

        Returns:
            True if proof is valid, False otherwise
        """
        # Convert input to integer if it's a string
        if isinstance(input_data, str):
            x = int.from_bytes(input_data.encode(), "big")
        else:
            x = input_data

        x = x % self.p
        y = proof

        # Verify by squaring (which is much faster than taking square roots)
        for _ in range(self.iterations):
            y = pow(int(y), 2, self.p)

        # Need to handle negative value case
        if not self.quad_res(y, self.p):
            y = (-y) % self.p

        # Check if result matches expected value
        return x % self.p == y or (-x) % self.p == y
