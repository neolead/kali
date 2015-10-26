import random

MAX_WRONG = 6
WORDS = ("UBER", "LMMS", "RUBY", "LISP")

word = random.choice(WORDS)
so_far = "-" * len(word)

wrong = 0

used = []

while wrong < MAX_WRONG and so_far != word:
    print("\nYou've used the following letters:\n", used)
    print("\nSo far, the word is:\n", so_far)

    guess = raw_input("Please guess a letter:").upper()
    while guess in used:
        guess = raw_input("you had guessed it, please guess another:").upper()

    used.append(guess)
    print("now the used letters is ", used)

    if guess in word:
        print("\nYes!", guess, "is in the word!")

        new = ""
        for i in range(len(word)):
            if guess == word[i]:
                new += guess
            else:
                new += so_far[i]
        so_far = new
    else:
        print("\n SORRY", guess, "isn't in the word")
    wrong += 1

if so_far == word:
    print("YOU WIN")
else:
    print("YOU LOSE", "WORD IS ", word)
print("\n input enter to exit")
