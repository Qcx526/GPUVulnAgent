#include <cuda_runtime.h>
#include <cstdio>
#include <vector>

#define CUDA_CHECK(call) do { \
    cudaError_t err = (call); \
    if (err != cudaSuccess) { \
        fprintf(stderr, "CUDA ERROR: %s\n", \
                cudaGetErrorString(err)); \
        return 1; \
    } \
} while (0)

__global__ void vector_add(
    const int* a,
    const int* b,
    int* c,
    int n
) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) {
        c[i] = a[i] + b[i];
    }
}

int main() {
    int device = 0;
    cudaDeviceProp prop;

    CUDA_CHECK(cudaSetDevice(device));
    CUDA_CHECK(cudaGetDeviceProperties(&prop, device));

    printf("GPU: %s\n", prop.name);
    printf("Compute Capability: %d.%d\n",
           prop.major, prop.minor);

    const int N = 1 << 20;
    size_t bytes = N * sizeof(int);

    std::vector<int> a(N, 10);
    std::vector<int> b(N, 20);
    std::vector<int> c(N, 0);

    int *da, *db, *dc;

    CUDA_CHECK(cudaMalloc(&da, bytes));
    CUDA_CHECK(cudaMalloc(&db, bytes));
    CUDA_CHECK(cudaMalloc(&dc, bytes));

    CUDA_CHECK(cudaMemcpy(da, a.data(), bytes,
                          cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(db, b.data(), bytes,
                          cudaMemcpyHostToDevice));

    vector_add<<<(N + 255) / 256, 256>>>(da, db, dc, N);

    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());

    CUDA_CHECK(cudaMemcpy(c.data(), dc, bytes,
                          cudaMemcpyDeviceToHost));

    for (int i = 0; i < N; i++) {
        if (c[i] != 30) {
            fprintf(stderr, "VERIFY FAILED at %d\n", i);
            return 1;
        }
    }

    printf("CUDA_KERNEL=PASS\n");
    printf("ELEMENTS=%d\n", N);
    printf("RESULT=%d\n", c[0]);

    cudaFree(da);
    cudaFree(db);
    cudaFree(dc);

    return 0;
}
