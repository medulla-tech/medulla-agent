import argparse
import xml.etree.ElementTree as ET
import sys

def main():
    parser = argparse.ArgumentParser(description='Extrait les données XML selon un XPath spécifié et écrit les résultats dans un fichier.')
    parser.add_argument('-f', '--file', required=True, help='Fichier XML d\'entrée')
    parser.add_argument('--pathxml', required=True, help='XPath à utiliser pour la recherche')
    parser.add_argument('--result-search', required=True, help='Fichier de sortie pour les résultats')
    parser.add_argument('--verbose', action='store_true', default=False,
                        help='Affiche un message de confirmation si activé.')
    args = parser.parse_args()

    try:
        tree = ET.parse(args.file)
        root = tree.getroot()

        elements = root.findall(".//" + args.pathxml)

        if not elements:
            print(f"Aucun élément trouvé avec l'XPath: {args.pathxml}")
            sys.exit(1)

        with open(args.result_search, 'w') as output_file:
            for element in elements:
                if element.text and element.text.strip():
                    output_file.write(element.text.strip() + '\n')
                else:
                    output_file.write('N/A\n')

        if args.verbose:
            print(f"Résultats écrits dans le fichier: {args.result_search}")

    except ET.ParseError as e:
        print(f"Erreur de parsing XML: {e}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"Fichier d'entrée non trouvé: {args.file}")
        sys.exit(1)
    except Exception as e:
        print(f"Une erreur inattendue s'est produite: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
