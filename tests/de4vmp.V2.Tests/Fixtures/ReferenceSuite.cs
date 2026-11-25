namespace de4vmp.V2.Tests.Fixtures;

/// <summary>
/// Self-authored reference class for managed object, field, and virtual-call tests (Tier 4).
/// </summary>
public class ReferenceCounter {
    public int Value;

    public ReferenceCounter(int initial) {
        Value = initial;
    }

    public virtual int AddAndGet(int delta) {
        Value += delta;
        return Value;
    }
}

/// <summary>
/// Ground-truth C# reference methods used as the behavioral oracle for synthetic VM Tiers 1-4.
/// Every devirtualized method must match these methods bit-for-bit across boundary and random inputs.
/// </summary>
public static class ReferenceSuite {
    // --- Arithmetic & Bitwise (Tiers 1-4) ---
    public static int AddSubMul(int a, int b) {
        int sum = a + b;
        int diff = a - b;
        return (sum * 3) - diff;
    }

    public static int XorShiftMix(int x, int y) {
        int v = (x ^ y) + ((x & 0xFF) << 3);
        return v ^ (y >> 2);
    }

    public static int Clamp(int v, int min, int max) {
        if (v < min)
            return min;
        if (v > max)
            return max;
        return v;
    }

    // --- Control Flow & Loops (Tiers 1-4) ---
    public static int SumRange(int n) {
        int acc = 0;
        for (int i = 1; i <= n; i++) {
            acc += i;
        }
        return acc;
    }

    public static int Gcd(int a, int b) {
        if (a < 0) a = -a;
        if (b < 0) b = -b;
        while (b != 0) {
            int t = a % b;
            a = b;
            b = t;
        }
        return a;
    }

    public static int ClassifyScore(int score) {
        if (score < 0) return -1;
        if (score < 50) return 0;
        if (score < 80) return 1;
        return 2;
    }

    // --- Arrays, Boxing & Managed Objects (Tier 4) ---
    public static int SumArray(int[] arr) {
        int acc = 0;
        for (int i = 0; i < arr.Length; i++) {
            acc += arr[i];
        }
        return acc;
    }

    public static int CounterIncrement(ReferenceCounter counter, int delta) {
        int before = counter.Value;
        int after = counter.AddAndGet(delta);
        return before + after;
    }

    public static ReferenceCounter MakeCounter(int start) {
        var c = new ReferenceCounter(start);
        c.Value = c.Value + 10;
        return c;
    }

    // --- Exception Handling (Tier 4) ---
    public static int SafeDivide(int a, int b) {
        try {
            return a / b;
        }
        catch (DivideByZeroException) {
            return -1;
        }
    }

    public static int TryFinallyAccumulate(int a, int b) {
        int acc = a;
        try {
            acc += b * 2;
        }
        finally {
            acc += 7;
        }
        return acc;
    }
}
