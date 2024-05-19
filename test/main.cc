#include <drogon/drogon.h>
#include <gtest/gtest.h>

#include "unittests/JwtUtilTest.h"

using namespace drogon;

int main(int argc, char *argv[])
{
    std::promise<void> p1;
    std::future<void> f1 = p1.get_future();

    // Start the main loop on another thread
    std::thread thr([&]() {
        // Queues the promise to be fulfilled after starting the loop
        app().getLoop()->queueInLoop([&p1]() { p1.set_value(); });
        app().run();
    });

    // The future is only satisfied after the event loop started
    f1.get();

    testing::InitGoogleTest(&argc, argv);
    auto status = RUN_ALL_TESTS();

    // Ask the event loop to shutdown and wait
    app().getLoop()->queueInLoop([]() { app().quit(); });
    thr.join();
    return status;
}
