from app import Order, total

def test_total():
    assert total(Order("pen", 3, 2.0)) == 6.0
