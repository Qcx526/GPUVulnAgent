// vector_scale_v1.cu -- hand-written source for traceability experiment P21R2-CUDA
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <cuda_runtime.h>

#define VERSION_STR "v2"
#define COEFF 3.0f
#define N 1024
#define TPB 256

#define CUDA_CHECK(call)                                                 \
    do {                                                                 \
        cudaError_t err__ = (call);                                      \
        if (err__ != cudaSuccess) {                                      \
            std::fprintf(stderr, "CUDA_ERROR %s at %s:%d\n",             \
                         cudaGetErrorString(err__), __FILE__, __LINE__); \
            std::exit(1);                                                \
        }                                                                \
    } while (0)

__global__ void vec_scale(const float * __restrict__ in,
                          float * __restrict__ out,
                          int n)
{
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) {
        out[i] = in[i] * COEFF;
    }
}

int main(void)
{
    int dev = 0;
    cudaDeviceProp prop;
    CUDA_CHECK(cudaGetDevice(&dev));
    CUDA_CHECK(cudaGetDeviceProperties(&prop, dev));

    size_t bytes = (size_t)N * sizeof(float);
    float *h_in  = (float *)std::malloc(bytes);
    float *h_out = (float *)std::malloc(bytes);
    float *h_ref = (float *)std::malloc(bytes);
    if (!h_in || !h_out || !h_ref) { std::fprintf(stderr, "host alloc failed\n"); return 1; }

    for (int i = 0; i < N; ++i) {
        h_in[i]  = (float)(i + 1);
        h_ref[i] = h_in[i] * COEFF;   /* CPU reference */
    }

    float *d_in = NULL, *d_out = NULL;
    CUDA_CHECK(cudaMalloc((void **)&d_in, bytes));
    CUDA_CHECK(cudaMalloc((void **)&d_out, bytes));
    CUDA_CHECK(cudaMemcpy(d_in, h_in, bytes, cudaMemcpyHostToDevice));

    int blocks = (N + TPB - 1) / TPB;
    vec_scale<<<blocks, TPB>>>(d_in, d_out, N);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaMemcpy(h_out, d_out, bytes, cudaMemcpyDeviceToHost));

    int mismatches = 0, first_bad = -1;
    for (int i = 0; i < N; ++i) {
        if (std::fabs(h_out[i] - h_ref[i]) > 1e-5f) {
            if (first_bad < 0) first_bad = i;
            ++mismatches;
        }
    }

    std::printf("VERSION=%s\n", VERSION_STR);
    std::printf("MISMATCHES=%d\n", mismatches);
    std::printf("SAMPLE=%.6f\n", h_out[0]);
    std::printf("DETAIL COEFF=%.6f N=%d BLOCKS=%d TPB=%d FIRST_BAD=%d\n",
                (double)COEFF, N, blocks, TPB, first_bad);
    std::printf("GPU=%s\n", prop.name);

    CUDA_CHECK(cudaFree(d_in));
    CUDA_CHECK(cudaFree(d_out));
    std::free(h_in); std::free(h_out); std::free(h_ref);
    return (mismatches == 0) ? 0 : 2;
}
