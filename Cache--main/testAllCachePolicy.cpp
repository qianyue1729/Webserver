#include <iostream>
#include <string>
#include <chrono>
#include <vector>
#include <iomanip>
#include <random>
#include <algorithm>

#include "KLfuCache.h"
#include "KLruCache.h"
#include "KArcCache/KArcCache.h"

class Timer {
public:
    Timer() : start_(std::chrono::high_resolution_clock::now()) {}
    
    double elapsed() {
        auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(now - start_).count();
    }

private:
    std::chrono::time_point<std::chrono::high_resolution_clock> start_;
};

// 辅助函数：打印结果
void printResults(const std::string& testName, int capacity, 
                 const std::vector<int>& get_operations, 
                 const std::vector<int>& hits) {
    std::cout << "缓存大小: " << capacity << std::endl;
    std::cout << "LRU - 命中率: " << std::fixed << std::setprecision(2) 
              << (100.0 * hits[0] / get_operations[0]) << "%" << std::endl;
    std::cout << "LFU - 命中率: " << std::fixed << std::setprecision(2) 
              << (100.0 * hits[1] / get_operations[1]) << "%" << std::endl;
    std::cout << "ARC - 命中率: " << std::fixed << std::setprecision(2) 
              << (100.0 * hits[2] / get_operations[2]) << "%" << std::endl;
}

// 辅助函数：打印页面集合
void print_frame(const std::vector<int>& frame_pages) {
    for (auto& page : frame_pages) {
        std::cout << page << " ";
    }
    std::cout << std::endl;
}

void testHotDataAccess() {
    std::cout << "\n=== 测试场景1：热点数据访问测试 ===" << std::endl;
    
    const int CAPACITY = 5;             
    const int OPERATIONS = 100000;      
    const int HOT_KEYS = 3;            
    const int COLD_KEYS = 5000;        
    
    KamaCache::KLruCache<int, std::string> lru(CAPACITY);
    KamaCache::KLfuCache<int, std::string> lfu(CAPACITY);
    KamaCache::KArcCache<int, std::string> arc(CAPACITY);

    std::random_device rd;
    std::mt19937 gen(rd());
    
    std::array<KamaCache::KICachePolicy<int, std::string>*, 3> caches = {&lru, &lfu, &arc};
    std::vector<int> hits(3, 0);
    std::vector<int> get_operations(3, 0);

    // 先进行一系列put操作
    for (int i = 0; i < caches.size(); ++i) {
        for (int op = 0; op < OPERATIONS; ++op) {
            int key;
            if (op % 100 < 40) {  // 40%热点数据
                key = gen() % HOT_KEYS;
            } else {  // 60%冷数据
                key = HOT_KEYS + (gen() % COLD_KEYS);
            }
            std::string value = "value" + std::to_string(key);
            caches[i]->put(key, value);
        }
        
        // 然后进行随机get操作
        for (int get_op = 0; get_op < OPERATIONS/2; ++get_op) {
            int key;
            if (get_op % 100 < 40) {  // 40%概率访问热点
                key = gen() % HOT_KEYS;
            } else {  // 60%概率访问冷数据
                key = HOT_KEYS + (gen() % COLD_KEYS);
            }
            
            std::string result;
            get_operations[i]++;
            if (caches[i]->get(key, result)) {
                hits[i]++;
            }
        }
    }

    printResults("热点数据访问测试", CAPACITY, get_operations, hits);
}

void testLoopPattern() {
    std::cout << "\n=== 测试场景2：循环扫描测试 ===" << std::endl;
    
    const int CAPACITY = 3;            
    const int LOOP_SIZE = 200;         
    const int OPERATIONS = 50000;      
    
    KamaCache::KLruCache<int, std::string> lru(CAPACITY);
    KamaCache::KLfuCache<int, std::string> lfu(CAPACITY);
    KamaCache::KArcCache<int, std::string> arc(CAPACITY);

    std::array<KamaCache::KICachePolicy<int, std::string>*, 3> caches = {&lru, &lfu, &arc};
    std::vector<int> hits(3, 0);
    std::vector<int> get_operations(3, 0);

    std::random_device rd;
    std::mt19937 gen(rd());

    // 先填充数据
    for (int i = 0; i < caches.size(); ++i) {
        for (int key = 0; key < LOOP_SIZE * 2; ++key) {
            std::string value = "loop" + std::to_string(key);
            caches[i]->put(key, value);
        }
        
        // 然后进行访问测试
        int current_pos = 0;
        for (int op = 0; op < OPERATIONS; ++op) {
            int key;
            if (op % 100 < 70) {  // 70%顺序扫描
                key = current_pos;
                current_pos = (current_pos + 1) % LOOP_SIZE;
            } else if (op % 100 < 85) {  // 15%随机跳跃
                key = gen() % LOOP_SIZE;
            } else {  // 15%访问范围外数据
                key = LOOP_SIZE + (gen() % LOOP_SIZE);
            }
            
            std::string result;
            get_operations[i]++;
            if (caches[i]->get(key, result)) {
                hits[i]++;
            }
        }
    }

    printResults("循环扫描测试", CAPACITY, get_operations, hits);
}

void testWorkloadShift() {
    std::cout << "\n=== 测试场景3：工作负载剧烈变化测试 ===" << std::endl;
    
    const int CAPACITY = 4;            
    const int OPERATIONS = 80000;      
    const int PHASE_LENGTH = OPERATIONS / 5;
    
    KamaCache::KLruCache<int, std::string> lru(CAPACITY);
    KamaCache::KLfuCache<int, std::string> lfu(CAPACITY);
    KamaCache::KArcCache<int, std::string> arc(CAPACITY);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::array<KamaCache::KICachePolicy<int, std::string>*, 3> caches = {&lru, &lfu, &arc};
    std::vector<int> hits(3, 0);
    std::vector<int> get_operations(3, 0);

    // 先填充一些初始数据
    for (int i = 0; i < caches.size(); ++i) {
        for (int key = 0; key < 1000; ++key) {
            std::string value = "init" + std::to_string(key);
            caches[i]->put(key, value);
        }
        
        // 然后进行多阶段测试
        for (int op = 0; op < OPERATIONS; ++op) {
            int key;
            // 根据不同阶段选择不同的访问模式
            if (op < PHASE_LENGTH) {  // 热点访问
                key = gen() % 5;
            } else if (op < PHASE_LENGTH * 2) {  // 大范围随机
                key = gen() % 1000;
            } else if (op < PHASE_LENGTH * 3) {  // 顺序扫描
                key = (op - PHASE_LENGTH * 2) % 100;
            } else if (op < PHASE_LENGTH * 4) {  // 局部性随机
                int locality = (op / 1000) % 10;
                key = locality * 20 + (gen() % 20);
            } else {  // 混合访问
                int r = gen() % 100;
                if (r < 30) {
                    key = gen() % 5;
                } else if (r < 60) {
                    key = 5 + (gen() % 95);
                } else {
                    key = 100 + (gen() % 900);
                }
            }
            
            std::string result;
            get_operations[i]++;
            if (caches[i]->get(key, result)) {
                hits[i]++;
            }
            
            // 随机进行put操作，更新缓存内容
            if (gen() % 100 < 30) {  // 30%概率进行put
                std::string value = "new" + std::to_string(key);
                caches[i]->put(key, value);
            }
        }
    }

    printResults("工作负载剧烈变化测试", CAPACITY, get_operations, hits);
}


// Belady测试函数
int belady(std::vector<int>& token, int frameNum) {
    std::cout << "\n=== 测试场景4：Belady 现象测试 ===" << std::endl;
    std::cout << "页面访问流: ";
    print_frame(token);

    int n = token.size();
    int pages_missing_count = 0;
    int l = 0, r = 0;

    std::vector<int> pages_array;
    std::unordered_map<int, int> pages_map;

    while (r < n) {
        int last = token[r];
        if (pages_map[last] > 0) {
            r++;
            continue;
        }
        pages_missing_count++;
        if (r - l + 1 > frameNum) {
            pages_map[pages_array[0]]--;
            pages_array.erase(pages_array.begin());
        }
        pages_array.push_back(last);
        pages_map[last]++;
        r++;
    }
    return pages_missing_count;
}

void testBeladyPhenomenon() {
    const int FRAME_NUM = 3;
    const int VECTOR_MIN_SIZE = 10;
    const int VECTOR_MAX_SIZE = 15;
    const int VALUE_MIN = 0;
    const int VALUE_MAX = 3;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(VALUE_MIN, VALUE_MAX);

    auto generateRandomVector = [&]() {
        std::vector<int> result;
        int size = VECTOR_MIN_SIZE + (gen() % (VECTOR_MAX_SIZE - VECTOR_MIN_SIZE + 1));
        for (int i = 0; i < size; ++i) {
            result.push_back(dis(gen));
        }
        return result;
    };

    std::vector<int> token = generateRandomVector();
    
    int missing_count_3 = belady(token, 3);
    int missing_count_4 = belady(token, 4);

    std::cout << "物理帧为3时缺页次数: " << missing_count_3 << std::endl;
    std::cout << "物理帧为4时缺页次数: " << missing_count_4 << std::endl;

    if(missing_count_3 < missing_count_4){
        std::cout << "物理帧为3时的缺页次数少于物理帧为4的缺页次数，此时出现Belady现象" << std::endl; 
    }
}


int main() {
    testHotDataAccess();
    testLoopPattern();
    testWorkloadShift();
    testBeladyPhenomenon();
    return 0;
}