using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Decipher
{
    internal class Statistics
    {
        // An occurence of a length-N sequence of characters.
        public struct NGram
        {
            public int Length { get; private set; }
            public int Position { get; private set; }

            public NGram(int length, int position)
            {
                this.Length = length;
                this.Position = position;
            }
        }

        // Helper subclass of Dictionary that shares some functionality.
        public class DictionaryCounter<T> : Dictionary<T, int>
        {
            public void CountItems(T item, int add)
            {
                int existing;

                if (this.TryGetValue(item, out existing))
                    this[item] = existing + add;
                else
                    this.Add(item, add);
            }

            public void CountItems(T item)
            {
                CountItems(item, 1);
            }

            public List<KeyValuePair<T, int>> SortedList()
            {
                var list = this.ToList();

                list.Sort((kvp1, kvp2) => {
                    return kvp2.Value - kvp1.Value;
                });

                return list;
            }

            public static DictionaryCounter<string> CountLists(Dictionary<string, List<NGram>> input)
            {
                DictionaryCounter<string> counts = new DictionaryCounter<string>();

                foreach (string gram in input.Keys)
                {
                    counts.CountItems(gram, input[gram].Count);
                }


                return counts;
            }
        }

        public static Dictionary<char, double> EnglishCharacterStats()
        {
            Dictionary<char, double> englishLetterStats = new Dictionary<char, double>();

            englishLetterStats.Add('a', 0.0855);
            englishLetterStats.Add('b', 0.0160);
            englishLetterStats.Add('c', 0.0316);
            englishLetterStats.Add('d', 0.0387);
            englishLetterStats.Add('e', 0.1210);
            englishLetterStats.Add('f', 0.0218);
            englishLetterStats.Add('g', 0.0209);
            englishLetterStats.Add('h', 0.0496);
            englishLetterStats.Add('i', 0.0733);
            englishLetterStats.Add('j', 0.0022);
            englishLetterStats.Add('k', 0.0081);
            englishLetterStats.Add('l', 0.0421);
            englishLetterStats.Add('m', 0.0253);
            englishLetterStats.Add('n', 0.0717);
            englishLetterStats.Add('o', 0.0747);
            englishLetterStats.Add('p', 0.0207);
            englishLetterStats.Add('q', 0.0010);
            englishLetterStats.Add('r', 0.0633);
            englishLetterStats.Add('s', 0.0673);
            englishLetterStats.Add('t', 0.0894);
            englishLetterStats.Add('u', 0.0268);
            englishLetterStats.Add('v', 0.0106);
            englishLetterStats.Add('w', 0.0183);
            englishLetterStats.Add('x', 0.0019);
            englishLetterStats.Add('y', 0.0172);
            englishLetterStats.Add('z', 0.0011);

            return englishLetterStats;
        }

        // Record each occurence of sequences of length n. Used for Kasiski testing and for interactive substitution cracking.
        public static Dictionary<string, List<NGram>> NGramCount(string s, int n)
        {
            Dictionary<string, List<NGram>> counts = new Dictionary<string, List<NGram>>();

            for (int i = 0; i + n < s.Length; i++)
            {
                string sub = s.Substring(i, n);

                List<NGram> list;

                if (!counts.TryGetValue(sub, out list))
                {
                    counts.Add(sub, new List<NGram>());
                    counts.TryGetValue(sub, out list);
                }

                list.Add(new NGram(n, i));
            }

            return counts;
        }

        // Count characters.
        public static DictionaryCounter<char> CharacterCount(string s)
        {
            var counts = new DictionaryCounter<char>();

            foreach (char c in s)
                counts.CountItems(c);

            return counts;
        }

        // Check how many dictionary words appear in the given text. Does not accurately account for overlapping words.
        public static int DictionaryCheck(string s, HashSet<string> dict)
        {
            // Example breaking and checking against dictionary
            int hits = 0;

            // Check for dictionary words
            // fow = front of word
            for (int fow = 0; fow < s.Length - 1; fow++)
            {
                for (int length = 2; length + fow < s.Length && length <= 7; length++)
                {
                    string testWord = s.Substring(fow, length);

                    // Dictionary hit
                    if (dict.Contains(testWord.ToUpper()))
                        hits++;
                }
            }

            return hits;
        }
    }
}
