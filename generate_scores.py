import pickle
import torch
import pandas as pd
from src.models.sequence_model import SessionSequenceDataset, ARGUSTransformerDetector, score_dataset

def main():
    print('Loading data...')
    sf = pd.read_parquet('data/processed/session_features.parquet')
    
    print('Loading meta...')
    with open('src/models/transformer_meta.pkl', 'rb') as f:
        meta = pickle.load(f)
        
    feature_cols = meta['feature_cols']
    scaler = meta['scaler']
    SEQ_LEN = meta['seq_len']
    
    print('Scaling...')
    sf_scaled = sf.copy()
    sf_scaled[feature_cols] = scaler.transform(sf[feature_cols])
    
    print('Creating dataset...')
    dataset = SessionSequenceDataset(sf_scaled, feature_cols, SEQ_LEN)
    
    print('Loading model...')
    model = ARGUSTransformerDetector(
        n_features=len(feature_cols),
        d_model=meta['d_model'],
        nhead=meta['n_heads'],
        num_layers=meta['n_layers'],
        dim_ff=meta['dim_ff'],
        dropout=meta['dropout'],
        seq_len=SEQ_LEN
    )
    model.load_state_dict(torch.load('src/models/transformer_weights.pt', weights_only=True))
    model.eval()
    
    print('Scoring...')
    scores = score_dataset(model, dataset)
    
    rows = []
    for (entity_id, session_id), score in zip(dataset.meta, scores):
        rows.append({'session_id': session_id, 'transformer_score': float(score)})
        
    df = pd.DataFrame(rows).drop_duplicates('session_id')
    df.to_parquet('data/processed/transformer_scores.parquet', index=False)
    print(f'Saved {len(df)} scores. Mean: {df["transformer_score"].mean():.6f}')

if __name__ == '__main__':
    main()
