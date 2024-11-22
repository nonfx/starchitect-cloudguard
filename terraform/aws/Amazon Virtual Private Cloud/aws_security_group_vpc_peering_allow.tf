resource "aws_vpc" "example_vpc" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_vpc" "peer_vpc" {
  cidr_block = "10.1.0.0/16"
}

resource "aws_vpc_peering_connection" "example_peering" {
  vpc_id        = aws_vpc.example_vpc.id
  peer_vpc_id   = aws_vpc.peer_vpc.id
  auto_accept   = true
}

resource "aws_route_table" "example_route_table" {
  vpc_id = aws_vpc.example_vpc.id

  route {
    cidr_block = "10.1.1.0/24"
    gateway_id = aws_vpc_peering_connection.example_peering.id
  }
}
