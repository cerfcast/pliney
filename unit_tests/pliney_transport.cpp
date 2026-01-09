#include <gtest/gtest.h>
#include <packetline/constants.hpp>
#include <pisa/pisa.h>
#include <string>

#include "lib/safety.hpp"
#include "gtest/gtest.h"

TEST(PlineyTransport, from_native_transport) {
  EXPECT_EQ(Pliney::Transport::ICMP, Pliney::from_native_transport(PLINEY_ICMP));
  EXPECT_EQ(Pliney::Transport::ICMP6, Pliney::from_native_transport(PLINEY_ICMP6));
  EXPECT_EQ(Pliney::Transport::UDP, Pliney::from_native_transport(PLINEY_UDP));
  EXPECT_EQ(Pliney::Transport::TCP, Pliney::from_native_transport(PLINEY_TCP));
}

TEST(PlineyTransport, to_native_transport) {
  EXPECT_EQ(PLINEY_ICMP, Pliney::to_native_transport(Pliney::Transport::ICMP));
  EXPECT_EQ(PLINEY_ICMP6, Pliney::to_native_transport(Pliney::Transport::ICMP6));
  EXPECT_EQ(PLINEY_TCP, Pliney::to_native_transport(Pliney::Transport::TCP));
  EXPECT_EQ(PLINEY_UDP, Pliney::to_native_transport(Pliney::Transport::UDP));
}

TEST(PlineyTransport, to_native_transport_unreachable) {
  EXPECT_THROW(Pliney::from_native_transport(0), PlineyUnreachable);
}






