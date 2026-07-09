#pragma once
// PUBLIC slicer data used to self-validate / locate the key in-process.
// The modulus N is the public key; the envelopes are signed messages.
// Both are public - safe to embed. The SECRET p/q/d are recovered from
// the live plugin heap. Source: cached_envelopes_master.json + public key.
#include <vector>
#include "envelope.h"

// Slicer PUBLIC RSA-2048 modulus N (locate the private factor via N mod p == 0).
inline const char* SLICER_PUBLIC_N_HEX = "e201171629c05d1b15a5db951e98b78c25a75489f7edbcb1759a0bbc15bf610af498472b16ba182982d0475d5e1d162752582700282fd1bab3311d24108cb32932abb3d330e5d2950a8dcbee904169b209286604a01451ec80788e8f0256786f802fd6f4a5d6cff95c435c6c9836228cad8fe67452da64df84bfefa0f7f12ea7359de9b7621c630abbafc3e031f77e2a785a29ca3df9983e8f1cd519963951bdc3c9766dd1e80ca4b6ad65697b6269790f6cc6c35f997021aa55ab6a36f06340e3d1264717204853e592471462e9db937ab3bc1148f9148aca22a62932f154e0b672c223033c49c0efc921119b2d3687d5f4345da995d37c814ae24a09a287d1";

inline std::vector<Envelope> embedded_test_envelopes() {
    std::vector<Envelope> v;
    v.push_back({ "{\"print\":{\"ams_id\":1,\"command\":\"ams_change_filament\",\"curr_temp\":200,\"sequence_id\":\"a22683_acf_u00124\",\"slot_id\":255,\"tar_temp\":200,\"target\":255}}", "ZfMotuJ6YUgpHGAiZpjXlxQu10NLC+4TJhIbEIo39GB5Ha4l8zCe0IIXxvTa30QkbDgqUREo6Ik2EjAYzhiW2Q3TrqDmFOEdpCUgna2a+ul4OlpZlvN1g/CA4ZKJEy/U62Kws9CmM7vUsUEZPDN4MsOMHWpxy54fcychEiEzryWcq9gow5/rnqN/MHeONF9mypXsNIM74w7wyRPIO6lr/MjHcHqz2YS/jKhNtYAhWzcsmFFGUMgguun5+l70jBhxs6LNmSGgWWLOSxW620XU4wtOWsuvnfXbFsct7FvKBZvkyUGIlw04q4Q1oNAMusAydyVZREElLByPx3bMx5G65g==", "ams_change_filament" });
    v.push_back({ "{\"print\":{\"ams_id\":0,\"command\":\"ams_change_filament\",\"curr_temp\":200,\"sequence_id\":\"a22683_acf_u00125\",\"slot_id\":255,\"tar_temp\":220,\"target\":255}}", "0+/0ZYMe9Ne4qztgiFNgJ/JlYwONPczBCG9ZxJ7BVRAyOWk73Ul3oAtKkj9/hCjotx3kLMqaaBKsV7KuXCcHqJsqFzkqaHXPR9lj75PsrYLVnOs1NobW8O9MLWLMs2qhaTP7ir4OSSZ2nKNBATFnfegxCm0tW55ddpOvhANCN/bA8LMHkMti1JAuEa7VVaufHZHylMDQGIqPej9uiryYnUg49e7eOkZX2RpBYiVSdrmFo7CG1/LZqwEDjCNntRJbubr35v3SegTRIlsuISQTTr/94hiXMpvtmRCE0ekDlsNBMzk6/qloHm2mplckt+0tOLuq4A9AU8I8/j+bxsu9GQ==", "ams_change_filament" });
    v.push_back({ "{\"print\":{\"ams_id\":0,\"command\":\"ams_change_filament\",\"curr_temp\":200,\"sequence_id\":\"a23283_acf_u00123\",\"slot_id\":255,\"tar_temp\":200,\"target\":255}}", "xKOKoFVBKzjUHpByhSm+lnfu4/jlmimuYtxc8jxpJtuIrqwnlawYMOfQdGPD+58WPHPDquh1mrDJyvHncR+H5dCd6o9s8rfAfMGAjIHvpMm5KfTCq5MsLhscPKLXXfNI1nau0B/Nlqgv5/62GPFNObiQsWf44tZa6S+ZknjOcRL0pmWPYjowNxL2BaD2iZ/s7ky8VvHbtb+UeSdcunYanKIY8HTxreagcPCyqTuQ6AnuBdMzW8pROwsDZIbMrAJS24cD5whoZd9nwmt5aXpPlNngMT2p8KvvwPWZ8GUE8dVcNODCvng1To4Ym0g45X2rMTkOIaMjIFpjb/Q/JBirTQ==", "ams_change_filament" });
    v.push_back({ "{\"print\":{\"ams_id\":0,\"command\":\"ams_change_filament\",\"curr_temp\":200,\"sequence_id\":\"a23599_acf_u00123\",\"slot_id\":255,\"tar_temp\":200,\"target\":255}}", "ODBXmKF2ZyXPL7ZoBPMHIge1LS+FSc/VPooJbVCNdFG2mNhZSJ2PC8uylaXf5jr8wznEpuTLJH7Gv9j7cpso4V0zE+KqbDGNbHLt+pO6Axaf47B0Bf0TFs84gPD2Y89FBnrPFhYv4aUF0ea4+d3AUyMlbWtCBafsBbLRZ0VYokO4x2z1Ti2kgRMBXqfxw4jGO2fltzj/LofBn7Tu0+zN20KaY14XaKs1f5InTOTZF4nlDWmtvr52Y6zCUr4fHziezHzgCjXsjmlw7ZoExjZNWxduYC1rMJLrEMcv6mDLvrcmiPphFhn099w/7+LjPTIyPygxRiz13b/fm88mANnM9A==", "ams_change_filament" });
    return v;
}
