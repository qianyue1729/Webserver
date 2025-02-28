#pragma once

#include "../KICachePolicy.h"
#include "KArcLruPart.h"
#include "KArcLfuPart.h"
#include <memory>

namespace KamaCache 
{

template<typename Key, typename Value>
class KArcCache : public KICachePolicy<Key, Value> 
{
public:
    explicit KArcCache(size_t capacity = 10, size_t transformThreshold = 2)
        : capacity_(capacity)
        , transformThreshold_(transformThreshold)
        , lruPart_(std::make_unique<ArcLruPart<Key, Value>>(capacity, transformThreshold))
        , lfuPart_(std::make_unique<ArcLfuPart<Key, Value>>(capacity, transformThreshold))
    {}

    ~KArcCache() override = default;

    void put(Key key, Value value) override 
    {
        bool inGhost = checkGhostCaches(key);
        
        if (!inGhost) 
        {
            if (lruPart_->put(key, value)) 
            {
                lfuPart_->put(key, value);
            }
        } else 
        {
            lruPart_->put(key, value);
        }
    }

    bool get(Key key, Value& value) override 
    {
        checkGhostCaches(key);

        bool shouldTransform = false;
        if (lruPart_->get(key, value, shouldTransform)) 
        {
            if (shouldTransform) 
            {
                lfuPart_->put(key, value);
            }
            return true;
        }
        return lfuPart_->get(key, value);
    }

    Value get(Key key) override 
    {
        Value value{};
        get(key, value);
        return value;
    }

private:
    bool checkGhostCaches(Key key) 
    {
        bool inGhost = false;
        if (lruPart_->checkGhost(key)) 
        {
            if (lfuPart_->decreaseCapacity()) 
            {
                lruPart_->increaseCapacity();
            }
            inGhost = true;
        } 
        else if (lfuPart_->checkGhost(key)) 
        {
            if (lruPart_->decreaseCapacity()) 
            {
                lfuPart_->increaseCapacity();
            }
            inGhost = true;
        }
        return inGhost;
    }

private:
    size_t capacity_;
    size_t transformThreshold_;
    std::unique_ptr<ArcLruPart<Key, Value>> lruPart_;
    std::unique_ptr<ArcLfuPart<Key, Value>> lfuPart_;
};

} // namespace KamaCache