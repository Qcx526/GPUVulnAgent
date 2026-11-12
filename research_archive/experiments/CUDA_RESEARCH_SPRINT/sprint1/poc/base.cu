// Baseline CUDA source for CVE-2025-23339 (cuobjdump DWARF .debug_abbrev).
// Compiled with -G so the cubin carries real DWARF .debug_* sections.
#include <cstdio>

struct Vec3 { float x, y, z; };

template <typename T>
__device__ T scale(T v, float s) { return v * s; }

__global__ void kern(float *out, const float *in, int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) {
        out[i] = in[i] * 2.0f + 1.0f;
    }
}

int main() {
    Vec3 v{1.f, 2.f, 3.f};
    v.x = scale<float>(v.x, 2.0f);
    printf("baseline %f\n", v.x);
    return 0;
}