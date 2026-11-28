#ifndef _CL_KEYSEARCH_DEVICE_H
#define _CL_KEYSEARCH_DEVICE_H

#include "KeySearchDevice.h"
#include "clContext.h"

typedef struct CLTargetList_
{
    cl_ulong mask = 0;
    cl_ulong size = 0;
    cl_mem ptr = nullptr;
} CLTargetList;


class CLKeySearchDevice : public KeySearchDevice {

private:
    cl::CLContext* _clContext = nullptr;
    cl::CLProgram* _clProgram = nullptr;
    cl::CLKernel* _initKeysKernel = nullptr;
    cl::CLKernel* _stepKernel = nullptr;
    cl::CLKernel* _stepKernelWithDouble = nullptr;

    uint64_t _globalMemSize = 0;
    uint64_t _pointsMemSize = 0;
    uint64_t _targetMemSize = 0;

    CLTargetList _deviceTargetList;

    secp256k1::uint256 _start;
    secp256k1::uint256 _stride = 1;

    std::vector<hash160> _targetList;
    std::vector<KeySearchResult> _results;

    int _blocks = 0;
    int _threads = 0;
    int _points = 0;

    cl_device_id _device = nullptr;

    int _compression = PointCompressionType::COMPRESSED;
    uint64_t _iterations = 0;

    std::string _deviceName;

    // Device memory
    cl_mem _chain = nullptr;
    cl_mem _x = nullptr;
    cl_mem _y = nullptr;
    cl_mem _xInc = nullptr;
    cl_mem _yInc = nullptr;
    cl_mem _privateKeys = nullptr;
    cl_mem _xTable = nullptr;
    cl_mem _yTable = nullptr;
    cl_mem _deviceResults = nullptr;
    cl_mem _deviceResultsCount = nullptr;
    cl_mem _targets = nullptr;

    // Private methods
    void generateStartingPoints();
    void setIncrementor(secp256k1::ecpoint& p);
    void allocateBuffers();
    void initializeBasePoints();

    void splatBigInt(unsigned int* dest, int idx, secp256k1::uint256& k);
    secp256k1::uint256 readBigInt(unsigned int* src, int idx);

    void selfTest();

    void setTargetsInternal();
    void setTargetsList();
    void setBloomFilter();
    void initializeBloomFilter(const std::vector<struct hash160>& targets, uint64_t mask);
    uint64_t getOptimalBloomFilterMask(double p, size_t n);

    void getResultsInternal();
    bool isTargetInList(const unsigned int hash[5]);
    void removeTargetFromList(const unsigned int hash[5]);

public:
    CLKeySearchDevice(uint64_t device, int threads, int pointsPerThread, int blocks = 0);
    virtual ~CLKeySearchDevice();

    virtual void init(const secp256k1::uint256& start, int compression, const secp256k1::uint256& stride) override;
    virtual void doStep() override;
    virtual void setTargets(const std::set<KeySearchTarget>& targets) override;
    virtual size_t getResults(std::vector<KeySearchResult>& results) override;
    virtual uint64_t keysPerStep() override;
    virtual std::string getDeviceName() override;
    virtual void getMemoryInfo(uint64_t& freeMem, uint64_t& totalMem) override;
    virtual secp256k1::uint256 getNextKey() override;
};

#endif // _CL_KEYSEARCH_DEVICE_H