#pragma once 

#include <cstring>
#include <list>
#include <memory>
#include <mutex>
#include <unordered_map>

#include "KICachePolicy.h"

namespace KamaCache
{

// 前向声明
// template 类模板
template<typename Key, typename Value> class KLruCache;

template<typename Key, typename Value>
class LruNode 
{
private:
    Key key_;
    Value value_;
    size_t accessCount_;  // 访问次数
    std::shared_ptr<LruNode<Key, Value>> prev_;  
    std::shared_ptr<LruNode<Key, Value>> next_;

public:
    // 成员变量初始化 把传入的key和value放进去
    LruNode(Key key, Value value)
        : key_(key)
        , value_(value)
        , accessCount_(1) 
        , prev_(nullptr)
        , next_(nullptr)
    {}

    // 提供必要的访问器
    Key getKey() const { return key_; }
    Value getValue() const { return value_; }
    void setValue(const Value& value) { value_ = value; }
    size_t getAccessCount() const { return accessCount_; }
    void incrementAccessCount() { ++accessCount_; }

    // 友元类
    // 可以直接访问LruNode类的private成员和protected成员
    // 友元类不具有继承性 KLruCache的子类不能继承KLruCache的友元类
    // 友元类具有单向性 KLruCache可以访问LruNode的成员，反之不一定
    friend class KLruCache<Key, Value>;
};


template<typename Key, typename Value>
class KLruCache : public KICachePolicy<Key, Value>
{
public:
    // using关键字 定义类型别名
    using LruNodeType = LruNode<Key, Value>;
    using NodePtr = std::shared_ptr<LruNodeType>;
    using NodeMap = std::unordered_map<Key, NodePtr>;

    KLruCache(int capacity) // capacity作为缓存大小
        : capacity_(capacity)
    {
        initializeList();
    }

    ~KLruCache() override = default;

    // 添加缓存
    void put(Key key, Value value) override
    {
        if (capacity_ <= 0)
            return;
    
        std::lock_guard<std::mutex> lock(mutex_);
        // 这里的it是一个迭代器 如果不存在指向end
        auto it = nodeMap_.find(key);
        if (it != nodeMap_.end())
        {
            // 如果在当前容器中,则更新value,并调用get方法，代表该数据刚被访问
            updateExistingNode(it->second, value);
            return ;
        }

        addNewNode(key, value);
    }

    bool get(Key key, Value& value) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = nodeMap_.find(key);
        if (it != nodeMap_.end())
        {
            moveToMostRecent(it->second);
            value = it->second->getValue();
            return true;
        }
        return false;
    }

    Value get(Key key) override
    {
        Value value{};
        // memset(&value, 0, sizeof(value));   // memset 是按字节设置内存的，对于复杂类型（如 string）使用 memset 可能会破坏对象的内部结构
        get(key, value);
        return value;
    }

    // 删除指定元素
    void remove(Key key) 
    {   
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = nodeMap_.find(key);
        if (it != nodeMap_.end())
        {
            removeNode(it->second);
            nodeMap_.erase(it); // 去重
        }
    }

private:
    void initializeList()
    {
        // 创建首尾虚拟节点
        dummyHead_ = std::make_shared<LruNodeType>(Key(), Value());
        dummyTail_ = std::make_shared<LruNodeType>(Key(), Value());
        dummyHead_->next_ = dummyTail_;
        dummyTail_->prev_ = dummyHead_;
    }

    void updateExistingNode(NodePtr node, const Value& value) 
    {
        node->setValue(value);
        moveToMostRecent(node);
    }

    void addNewNode(const Key& key, const Value& value) 
    {
       if (nodeMap_.size() >= capacity_) 
       {
           evictLeastRecent();
       }

       NodePtr newNode = std::make_shared<LruNodeType>(key, value);
       insertNode(newNode);
       nodeMap_[key] = newNode;
    }

    // 将该节点移动到最新的位置
    void moveToMostRecent(NodePtr node) 
    {
        removeNode(node);
        insertNode(node);
    }

    void removeNode(NodePtr node) 
    {
        node->prev_->next_ = node->next_;
        node->next_->prev_ = node->prev_;
    }

    // 从尾部插入结点
    void insertNode(NodePtr node) 
    {
        node->next_ = dummyTail_;
        node->prev_ = dummyTail_->prev_;
        dummyTail_->prev_->next_ = node;
        dummyTail_->prev_ = node;
    }

    // 驱逐最近最少访问
    void evictLeastRecent() 
    {
        NodePtr leastRecent = dummyHead_->next_;
        removeNode(leastRecent);
        nodeMap_.erase(leastRecent->getKey());
    }

private:
    int          capacity_; // 缓存容量
    NodeMap      nodeMap_; // key -> Node 
    std::mutex   mutex_;
    NodePtr       dummyHead_; // 虚拟头结点
    NodePtr       dummyTail_;
};

// LRU优化：Lru-k版本。 通过继承的方式进行再优化
template<typename Key, typename Value>
class KLruKCache : public KLruCache<Key, Value>
{
public:
    // capacity为缓存队列的大小 
    // historyCapacity为历史访问队列的大小
    // k为评判标准
    KLruKCache(int capacity, int historyCapacity, int k)
        : KLruCache<Key, Value>(capacity) // 调用基类构造 缓存队列和LruCache是一样的
        //unique_str只有唯一指向对象
        // 历史访问队列需要新建一个队列
        , historyList_(std::make_unique<KLruCache<Key, size_t>>(historyCapacity)) 
        , k_(k)
    {}

    Value get(Key key)
    {
        // 获取该数据访问次数
        int historyCount = historyList_->get(key);
        // 如果访问到数据，则更新历史访问记录节点值count++
        historyList_->put(key, ++historyCount); 
        
        // 从缓存中获取数据，不一定能获取到，因为可能不在缓存中
        return KLruCache<Key, Value>::get(key);
    }

    void put(Key key, Value value)
    {
        // 先判断是否存在于缓存中，如果存在于则直接覆盖，如果不存在则不直接添加到缓存
        if (KLruCache<Key, Value>::get(key) != "")
            KLruCache<Key, Value>::put(key, value);
        
        // 如果数据历史访问次数达到上限，则添加入缓存
        int historyCount = historyList_->get(key);
        historyList_->put(key, ++historyCount); 

        if (historyCount >= k_)
        {
            // 移除历史访问记录
            historyList_->remove(key);
            // 添加入缓存中
            KLruCache<Key, Value>::put(key, value);
        }
    }

private:
    int                                     k_; // 进入缓存队列的评判标准
    std::unique_ptr<KLruCache<Key, size_t>> historyList_; // 访问数据历史记录(value为访问次数)
}; 

// lru优化：对lru进行分片，提高高并发使用的性能
template<typename Key, typename Value>
class KHashLruCaches
{
public:
    KHashLruCaches(size_t capacity, int sliceNum)
        : capacity_(capacity)
        // 如果传入的sliceNum小于0，则使用hardware_concurrency()函数 查询系统支持的并发线程数 
        // 一个线程最多访问一个LRU切片 用除法可以获取单个LRU切片容纳的队列大小
        , sliceNum_(sliceNum > 0 ? sliceNum : std::thread::hardware_concurrency()) 
    {
        // static_cast<……> 用于类型转换（编译期）
        // ceil()函数用于向上取整 
        size_t sliceSize = std::ceil(capacity / static_cast<double>(sliceNum_)); // 获取每个分片的大小
        // 新建若干个队列
        for (int i = 0; i < sliceNum_; ++i)
        {
            lruSliceCaches_.emplace_back(new KLruCache<Key, Value>(sliceSize)); 
        }
    }

    void put(Key key, Value value)
    {
        // 获取key的hash值，并计算出对应的分片索引
        size_t sliceIndex = Hash(key) % sliceNum_;
        return lruSliceCaches_[sliceIndex]->put(key, value);
    }

    bool get(Key key, Value& value)
    {
        // 获取key的hash值，并计算出对应的分片索引
        size_t sliceIndex = Hash(key) % sliceNum_;
        return lruSliceCaches_[sliceIndex]->get(key, value);
    }

    Value get(Key key)
    {
        Value value;
        memset(&value, 0, sizeof(value));
        get(key, value);
        return value;
    }

private:
    // 将key转换为对应hash值
    size_t Hash(Key key)
    {
        std::hash<Key> hashFunc;
        return hashFunc(key);
    }

private:
    size_t                                              capacity_;  // 总容量
    int                                                 sliceNum_;  // 切片数量
    std::vector<std::unique_ptr<KLruCache<Key, Value>>> lruSliceCaches_; // 切片LRU缓存
    // 用一个向量包含一系列指针，指向一系列缓存队列
};

} // namespace KamaCache